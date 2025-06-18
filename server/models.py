from config import db, bcrypt, ma
from marshmallow import post_load, validates, ValidationError


class User(db.Model):
  __tablename__ = 'users'

  id = db.Column(db.Integer, primary_key=True)
  username = db.Column(db.String(30), nullable=False)
  _password_hash = db.Column(db.String, nullable=False)

  programs = db.relationship('Program', backref='user', lazy=True)

  def set_password(self, password):
    if len(password) < 8:
      raise ValidationError("Password must be at least 8 characters long.")
    password_hash = bcrypt.generate_password_hash(password.encode('utf-8'))
    self._password_hash = password_hash.decode('utf-8')

  def authenticate(self, password):
    return bcrypt.check_password_hash(self._password_hash, password.encode('utf-8'))
  
  def __repr__(self):
    return f'<User {self.username}>'
    
class Route(db.Model):
  __tablename__ = 'routes'

  id = db.Column(db.Integer, primary_key=True)
  location = db.Column(db.String(90), nullable=False)
  difficulty = db.Column(db.String(30), nullable=False)
  distance = db.Column(db.Float, nullable=False)

  programs = db.relationship('Program', backref='route', lazy=True)
    
  def __repr__(self):
    return f'<Route {self.distance}>'
  
class Style(db.Model):
  __tablename__ = 'styles'

  id = db.Column(db.Integer, primary_key=True)
  name = db.Column(db.String(30), nullable=False)
  description = db.Column(db.Text, nullable=False)

  programs = db.relationship('Program', backref='style', lazy=True)
    
  def __repr__(self):
    return f'<Style {self.name}>'
  

class Program(db.Model):
  __tablename__ = 'programs'

  id = db.Column(db.Integer, primary_key=True)
  title = db.Column(db.String(30), nullable=False)
  description = db.Column(db.Text, nullable=False)
  duration = db.Column(db.String, nullable=False)

  user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
  route_id = db.Column(db.Integer, db.ForeignKey('routes.id'), nullable=False)
  style_id = db.Column(db.Integer, db.ForeignKey('styles.id'), nullable=False)
    
  def __repr__(self):
    return f'<Program {self.title}>'
  
class UserSchema(ma.SQLAlchemyAutoSchema):
  class Meta:
    model = User
    load_instance = True
    exclude = ('_password_hash', 'programs')
  password = ma.String(load_only=True)

  @validates('username')
  def validate_username(self, _, username):
      if not username:
          raise ValidationError("Username cannot be empty")
      if not isinstance(username, str):
          raise ValidationError("Username must be a string")
      if len(username) < 3:
          raise ValidationError("Username must be at least 3 characters long")
      return username

  @post_load
  def make_user(self, data, **kwargs):
    if 'password' in data: 
      user = User(
        username=data['username'],
      )
      user.set_password(data['password'])
      return user
    return User(**data)
  
class RouteSchema(ma.SQLAlchemyAutoSchema):
  class Meta:
    model = Route
    load_instance = True
    exclude = ('programs',)

  @validates('distance')
  def validates_distance(self, distance):
    if not distance:
      raise ValidationError('Distance cannot be empty')
    if not isinstance(distance, (int, float)):
      raise ValidationError("Distance must be a number")
    if distance <= 0:
      raise ValidationError("Distance must be greater than 0")

class StyleSchema(ma.SQLAlchemyAutoSchema):
  class Meta:
    model = Style
    load_instance = True
    exclude = ('programs',)

  @validates('name')
  def validate_name(self, _, name):
    if not name:
      raise ValidationError("Name cannot be empty")
    if not isinstance(name, str):
      raise ValidationError("Name must be a string")
    if len(name) < 2:
      raise ValidationError("Name must be at least 2 characters long")
    return name

  @validates('description')
  def validate_description(self, _, description):
    if not description:
      raise ValidationError("Description cannot be empty")
    if not isinstance(description, str):
      raise ValidationError("Description must be a string")
    if len(description) < 10:
      raise ValidationError("Description must be at least 10 characters long")
    return description

class ProgramSchema(ma.SQLAlchemyAutoSchema):
  class Meta:
    model = Program
    load_instance = True
    include_fk = True

  @validates('title')
  def validate_title(self, _, title):
    if not title:
      raise ValidationError("Title cannot be empty")
    if not isinstance(title, str):
      raise ValidationError("Title must be a string")
    if len(title) < 3:
      raise ValidationError("Title must be at least 3 characters long")
    return title

  @validates('description')
  def validate_description(self, _, description):
    if not description:
      raise ValidationError("Description cannot be empty")
    if not isinstance(description, str):
      raise ValidationError("Description must be a string")
    if len(description) < 10:
      raise ValidationError("Description must be at least 10 characters long")
    return description

  @validates('duration')
  def validate_duration(self, _, duration):
    if not duration:
      raise ValidationError("Duration cannot be empty")
    if not isinstance(duration, str):
      raise ValidationError("Duration must be a string")
    return duration