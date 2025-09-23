from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity, create_access_token
from . import db, bcrypt
from .models import Product, User, Review, Tip, FAQ, SocialMedia, Favorite
from datetime import datetime

bp = Blueprint('routes', __name__)

# Função de verificação de admin (baseada em is_admin para ações gerais)
def admin_required():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user or not user.is_admin:
        return jsonify({"msg": "Acesso negado: apenas administradores"}), 403
    return None

# Função específica para verificação do ADMIN 7 (exclusão e criação de admins)
def admin_7_required():
    user_id = get_jwt_identity()
    if str(user_id) != "7":
        return jsonify({"msg": "Acesso negado: apenas o administrador (ID 7)"}), 403
    return None

@bp.route('/products', methods=['GET'])
def get_products():
    products = Product.query.all()
    print("Rota /products chamada")
    return jsonify({'message': 'Lista de produtos', 'products': [{'id': p.id, 'name': p.name, 'price': p.price} for p in products]})

@bp.route('/reviews', methods=['GET'])
def get_reviews():
    reviews = Review.query.all()
    print("Rota /reviews chamada")
    return jsonify({'message': 'Lista de avaliações', 'reviews': [{'id': r.id, 'product_id': r.product_id, 'user_id': r.user_id, 'rating': r.rating} for r in reviews]})

@bp.route('/tips', methods=['GET'])
def get_tips():
    tips = Tip.query.all()
    print("Rota /tips chamada")
    return jsonify({'message': 'Lista de dicas', 'tips': [{'id': t.id, 'title': t.title} for t in tips]})

@bp.route('/faqs', methods=['GET'])
def get_faqs():
    faqs = FAQ.query.all()
    print("Rota /faqs chamada")
    return jsonify({'message': 'Lista de FAQs', 'faqs': [{'id': f.id, 'question': f.question} for f in faqs]})

@bp.route('/social-media', methods=['GET'])
@jwt_required()
def get_social_media():
    social_media = SocialMedia.query.all()
    print("Rota /social-media chamada")
    return jsonify({'message': 'Lista de redes sociais', 'social_media': [{'id': sm.id, 'platform': sm.platform, 'url': sm.url} for sm in social_media]})

@bp.route('/admin/social-media', methods=['POST'])
@jwt_required()
def create_social_media():
    admin_check = admin_required()
    if admin_check:
        return admin_check
    
    data = request.get_json()
    platform = data.get('platform')
    url = data.get('url')

    if not platform or not url:
        return jsonify({'error': 'platform e url são obrigatórios'}), 400

    new_social_media = SocialMedia(platform=platform, url=url)
    db.session.add(new_social_media)
    db.session.commit()

    return jsonify({'message': 'Rede social adicionada com sucesso', 'social_media': {'id': new_social_media.id, 'platform': new_social_media.platform, 'url': new_social_media.url}})

@bp.route('/admin/faqs', methods=['POST'])
@jwt_required()
def create_faq():
    admin_check = admin_required()
    if admin_check:
        return admin_check
    
    data = request.get_json()
    question = data.get('question')
    answer = data.get('answer')

    if not question or not answer:
        return jsonify({'error': 'question e answer são obrigatórios'}), 400

    new_faq = FAQ(question=question, answer=answer)
    db.session.add(new_faq)
    db.session.commit()

    return jsonify({'message': 'FAQ criado com sucesso', 'faq': {'id': new_faq.id, 'question': new_faq.question}})

@bp.route('/admin/tips', methods=['POST'])
@jwt_required()
def create_tip():
    admin_check = admin_required()
    if admin_check:
        return admin_check
    
    data = request.get_json()
    title = data.get('title')
    content = data.get('content')
    category = data.get('category')

    if not title or not content:
        return jsonify({'error': 'title e content são obrigatórios'}), 400

    new_tip = Tip(title=title, content=content, category=category)
    db.session.add(new_tip)
    db.session.commit()

    return jsonify({'message': 'Dica criada com sucesso', 'tip': {'id': new_tip.id, 'title': new_tip.title}})

@bp.route('/reviews', methods=['POST'])
@jwt_required()
def create_review():
    user_id = get_jwt_identity()
    data = request.get_json()
    product_id = data.get('product_id')
    rating = data.get('rating')
    comment = data.get('comment')

    if not product_id or not rating or rating < 1 or rating > 5:
        return jsonify({'error': 'product_id e rating (1-5) são obrigatórios'}), 400

    new_review = Review(product_id=product_id, user_id=user_id, rating=rating, comment=comment)
    db.session.add(new_review)
    db.session.commit()

    return jsonify({'message': 'Avaliação criada com sucesso', 'review': {'id': new_review.id, 'product_id': new_review.product_id, 'user_id': new_review.user_id, 'rating': new_review.rating}})

@bp.route('/products', methods=['POST'])
@jwt_required()
def create_product():
    admin_check = admin_required()
    if admin_check:
        return admin_check
    
    data = request.json
    name = data.get('name')
    price = data.get('price')
    description = data.get('description')
    type = data.get('type')
    image_url = data.get('image_url')
    video_url = data.get('video_url')

    if not name or not price or price < 0:
        return jsonify({'error': 'name e price válidos são obrigatórios'}), 400

    new_product = Product(name=name, price=price, description=description, type=type, image_url=image_url, video_url=video_url)
    db.session.add(new_product)
    db.session.commit()

    return jsonify({'message': 'Produto cadastrado com sucesso', 'product': {'id': new_product.id, 'name': new_product.name, 'price': new_product.price, 'description': new_product.description, 'type': new_product.type, 'image_url': new_product.image_url, 'video_url': new_product.video_url}})

@bp.route('/users', methods=['POST'])
def create_user():
    data = request.json
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    name = data.get('name')

    if not username or not email or not password or not name:
        return jsonify({'error': 'username, email, password e name são obrigatórios'}), 400

    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({'error': 'Usuário já existe'}), 400

    password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(username=username, email=email, password_hash=password_hash, name=name)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'Usuário cadastrado com sucesso', 'user': {'id': new_user.id, 'username': new_user.username, 'name': new_user.name}})

@bp.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'username e password são obrigatórios'}), 400

    user = User.query.filter_by(username=username).first()
    if user and bcrypt.check_password_hash(user.password_hash, password):
        access_token = create_access_token(identity=str(user.id))
        return jsonify({'message': 'Login bem-sucedido', 'token': access_token})
    return jsonify({'error': 'Credenciais inválidas'}), 401

@bp.route('/admin/users', methods=['POST'])
@jwt_required()
def create_admin_user():
    admin_check = admin_7_required()
    if admin_check:
        return admin_check
    
    data = request.json
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    name = data.get('name')

    if not username or not email or not password or not name:
        return jsonify({'error': 'username, email, password e name são obrigatórios'}), 400

    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({'error': 'Usuário já existe'}), 400

    existing_email = User.query.filter_by(email=email).first()
    if existing_email:
        return jsonify({'error': 'E-mail já está em uso'}), 400

    password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(username=username, email=email, password_hash=password_hash, name=name, is_admin=True)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'Usuário admin cadastrado com sucesso', 'user': {'id': new_user.id, 'username': new_user.username, 'name': new_user.name, 'is_admin': new_user.is_admin}})

@bp.route('/admin/users/<int:user_id>', methods=['DELETE'])
@jwt_required()
def delete_admin_user(user_id):
    admin_check = admin_7_required()
    if admin_check:
        return admin_check
    
    user = User.query.get_or_404(user_id)
    if not user.is_admin:
        return jsonify({'error': 'Somente usuários admin podem ser deletados por esta rota'}), 400
    
    db.session.delete(user)
    db.session.commit()

    return jsonify({'message': 'Usuário admin deletado com sucesso', 'user_id': user_id})

@bp.route('/admin/users', methods=['GET'])
@jwt_required()
def get_admin_users():
    admin_check = admin_required()
    if admin_check:
        return admin_check
    users = User.query.all()
    return jsonify({'message': 'Lista de usuários (somente admin)', 'users': [{'id': u.id, 'username': u.username, 'email': u.email, 'is_admin': u.is_admin} for u in users]})

@bp.route('/admin/products', methods=['POST'])
@jwt_required()
def create_admin_product():
    admin_check = admin_required()
    if admin_check:
        return admin_check
    
    data = request.json
    name = data.get('name')
    price = data.get('price')
    description = data.get('description')
    type = data.get('type')
    image_url = data.get('image_url')
    video_url = data.get('video_url')

    if not name or not price or price < 0:
        return jsonify({'error': 'name e price válidos são obrigatórios'}), 400

    new_product = Product(name=name, price=price, description=description, type=type, image_url=image_url, video_url=video_url)
    db.session.add(new_product)
    db.session.commit()

    return jsonify({'message': 'Produto criado com sucesso', 'product': {'id': new_product.id, 'name': new_product.name, 'price': new_product.price, 'description': new_product.description, 'type': new_product.type, 'image_url': new_product.image_url, 'video_url': new_product.video_url}})

@bp.route('/products/<int:product_id>', methods=['PUT'])
@jwt_required()
def update_product(product_id):
    admin_check = admin_required()
    if admin_check:
        return admin_check

    data = request.json
    name = data.get('name')
    price = data.get('price')

    if not name or price is None or price < 0:
        return jsonify({'error': 'name e price válidos são obrigatórios'}), 400

    product = Product.query.get(product_id)
    if not product:
        return jsonify({'error': 'Produto não encontrado'}), 404

    product.name = name
    product.price = price
    db.session.commit()

    return jsonify({'message': 'Produto atualizado com sucesso', 'product': {'id': product.id, 'name': product.name, 'price': product.price}})

@bp.route('/products/<int:product_id>', methods=['DELETE'])
@jwt_required()
def delete_product(product_id):
    admin_check = admin_required()
    if admin_check:
        return admin_check

    product = Product.query.get(product_id)
    if not product:
        return jsonify({'error': 'Produto não encontrado'}), 404

    db.session.delete(product)
    db.session.commit()

    return jsonify({'message': 'Produto deletado com sucesso'})

@bp.route('/favorites', methods=['POST'])
@jwt_required()
def create_favorite():
    user_id = get_jwt_identity()
    data = request.get_json()
    product_id = data.get('product_id')

    if not product_id:
        return jsonify({'error': 'product_id é obrigatório'}), 400

    product = Product.query.get(product_id)
    if not product:
        return jsonify({'error': 'Produto não encontrado'}), 404

    if Favorite.query.filter_by(user_id=user_id, product_id=product_id).first():
        return jsonify({'error': 'Produto já favoritado'}), 400

    new_favorite = Favorite(user_id=user_id, product_id=product_id)
    db.session.add(new_favorite)
    db.session.commit()

    return jsonify({'message': 'Produto favoritado com sucesso', 'favorite': {'user_id': user_id, 'product_id': product_id}})

@bp.route('/favorites', methods=['GET'])
@jwt_required()
def get_favorites():
    user_id = get_jwt_identity()
    favorites = Favorite.query.filter_by(user_id=user_id).all()
    return jsonify({'message': 'Lista de favoritos', 'favorites': [{'user_id': f.user_id, 'product_id': f.product_id, 'created_at': f.created_at.strftime('%Y-%m-%d %H:%M:%S')} for f in favorites]})

@bp.route('/favorites/<int:product_id>', methods=['DELETE'])
@jwt_required()
def delete_favorite(product_id):
    user_id = get_jwt_identity()
    favorite = Favorite.query.filter_by(user_id=user_id, product_id=product_id).first()

    if not favorite:
        return jsonify({'error': 'Favorito não encontrado'}), 404

    db.session.delete(favorite)
    db.session.commit()
    return jsonify({'message': 'Produto removido dos favoritos'})

@bp.route('/users/<int:user_id>', methods=['PUT'])
@jwt_required()
def update_user(user_id):
    current_user_id = get_jwt_identity()

    # Verifica se é o próprio usuário ou um admin
    if str(current_user_id) != str(user_id) and admin_required():
        return jsonify({'error': 'Você só pode editar seu próprio perfil'}), 403

    user = User.query.get_or_404(user_id)
    data = request.get_json()

    email = data.get('email')
    password = data.get('password')

    if 'username' in data:
        return jsonify({'error': 'Você não pode alterar o username'}), 400

    if email:
        if User.query.filter_by(email=email).first() and email != user.email:
            return jsonify({'error': 'Email já está em uso'}), 400
        user.email = email

    if password:
        user.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    try:
        db.session.commit()
        return jsonify({'message': 'Usuário atualizado com sucesso', 'user': {'id': user.id, 'username': user.username, 'email': user.email}})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Erro ao atualizar usuário', 'details': str(e)}), 500

@bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    return jsonify({'message': 'Logout realizado com sucesso. Por favor, limpe o token.'})

# Nova rota para o usuário deletar a própria conta
@bp.route('/users/<int:user_id>', methods=['DELETE'])
@jwt_required()
def delete_user(user_id):
    current_user_id = get_jwt_identity()
    if str(current_user_id) != str(user_id):
        return jsonify({'error': 'Você só pode deletar sua própria conta'}), 403

    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()

    return jsonify({'message': 'Conta deletada com sucesso'}), 200