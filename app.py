import bcrypt
from flask import Flask, json, jsonify, request
from flask_login import LoginManager, current_user, login_required, login_user, logout_user
from database import db
from dotenv import load_dotenv
from models.user import User
from models.meal import Meal

load_dotenv()
app = Flask(__name__)

app.config.from_object('config.Config')
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

def not_found(meal_id):
    return jsonify({"message": f"Refeição {meal_id} não encontrada"}), 404

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if username and password:
        user = User.query.filter_by(username=username).first()

        if user and  bcrypt.checkpw(password=str.encode(password), hashed_password=str.encode(user.password)):
            login_user(user)
            return jsonify({"message": "Autenticação realizada com sucesso"}), 200


    return jsonify({"message": "Credenciais Inválidas"}), 401


@app.route("/logout", methods=["GET"])
@login_required
def logout():
    logout_user()
    return jsonify({"message": "Logout realizado com sucesso"}), 200

@app.route("/user", methods=["POST"])
@login_required
def create_user():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if current_user.role != "admin":
        return jsonify({"message": "Apenas administradores podem criar novos usuários"}), 401
    
    if username and password:
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return jsonify({"message": "Nome de usuário não disponível"}), 400
        
        new_user = User(
            username=username, 
            password=bcrypt.hashpw(str.encode(password), bcrypt.gensalt()), 
            role="user"
        )
        db.session.add(new_user)
        db.session.commit()

        return jsonify({"message": "Usuário criado com sucesso"}), 200
    
    return jsonify({"message": "Dados inválidos"}), 400

@app.route("/meal", methods=["POST"])
@login_required
def create_meal():
    data = request.json
    name = data.get("name")
    description = data.get("description")
    consumed_at = data.get("consumed_at")
    is_diet = data.get("is_diet")

    if name and description and consumed_at and is_diet is not None:
        new_meal = Meal(
            name=name,
            description=description,
            consumed_at=consumed_at,
            is_diet=is_diet,
            user_id=current_user.id
        )

        db.session.add(new_meal)
        db.session.commit()

        return jsonify({"message": "Refeição criada com sucesso"}), 201
    
    return jsonify({"message": "Dados inválidos"}), 400

@app.route("/meal/<int:meal_id>", methods=["PUT"])
@login_required
def update_meal(meal_id):
    meal = Meal.query.filter_by(user_id=current_user.id, id=meal_id).first()

    if not meal:
        return not_found(meal_id)
    
    data = request.json
    name = data.get("name")
    description = data.get("description")
    consumed_at = data.get("consumed_at")
    is_diet = data.get("is_diet")

    meal.name = name or meal.name
    meal.description = description or meal.description
    meal.consumed_at = consumed_at or meal.consumed_at
    meal.is_diet = is_diet if is_diet is not None else meal.is_diet

    db.session.commit()
    return jsonify({"message": f"Refeição {meal_id} atualizada com sucesso"}), 200

@app.route("/meal/<int:meal_id>", methods=["DELETE"])
@login_required
def delete_meal(meal_id):
    meal = Meal.query.filter_by(user_id=current_user.id, id=meal_id).first()

    if not meal:
        return not_found(meal_id)
    
    db.session.delete(meal)
    db.session.commit()

    return jsonify({"message": f"Refeição {meal_id} excluída com sucesso"}), 200

@app.route("/meal/<int:meal_id>", methods=["GET"])
@login_required
def find_meal(meal_id):
    meal = Meal.query.filter_by(user_id=current_user.id, id=meal_id).first()

    if not meal:
        return not_found(meal_id)
    
    return jsonify(meal.as_dict())

@app.route("/meal", methods=["GET"])
@login_required
def list_meals():
    meals = Meal.query.filter_by(user_id=current_user.id).all()

    return jsonify([meal.as_dict() for meal in meals])


if __name__ == "__main__":
    app.run(debug=True)