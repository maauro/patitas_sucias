from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session, Markup  # type: ignore
from flask_sqlalchemy import SQLAlchemy  # type: ignore
from datetime import datetime
from zoneinfo import ZoneInfo
from functools import wraps
from sqlalchemy import func, extract # type: ignore
from sqlalchemy.exc import IntegrityError # type: ignore
import subprocess
import os
import json

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///patitas_sucias.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

_first_request = True

@app.before_request
def clear_session_on_start():
    global _first_request
    if _first_request:
        session.clear()
        _first_request = False
    # opcional: forzar login si no hay sesión
    if request.endpoint not in ('login', 'static') and not session.get('user_id'):
        return redirect(url_for('login'))

# Modelo
class Producto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    codigo = db.Column(db.String(50), unique=True, nullable=False)
    nombre = db.Column(db.String(100), nullable=False)
    precio = db.Column(db.Float, nullable=False)
    stock = db.Column(db.Integer, nullable=False)
    tiene_codigo = db.Column(db.Boolean, nullable=False, default=True)

# Modelo de Venta para guardar la venta completa
class Venta(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fecha = db.Column(db.DateTime, default=datetime.utcnow)
    total = db.Column(db.Float, nullable=False)
    detalles = db.Column(db.Text)  # se guarda como JSON
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id'))
    usuario = db.relationship('Usuario', backref='ventas')

# Nuevo modelo para Usuario
class Usuario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(50), nullable=False)
    apellido = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    rol_id = db.Column(db.Integer, nullable=False)  # 1: Admin, 2: Vendedor

@app.context_processor
def inject_now():
    return {'now': datetime.now}

@app.route('/login', methods=['GET', 'POST'])
def login():
    # 1) Si ya hay usuario en sesión, redirige a listar_productos
    if session.get('user_id'):
        return redirect(url_for('inicio'))

    # 2) Si viene del formulario…
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        usuario = Usuario.query.filter_by(username=username).first()
        if usuario and usuario.password == password:
            session['user_id']   = usuario.id
            session['username']  = usuario.username
            session['rol_id']    = usuario.rol_id
            session['nombre']    = usuario.nombre
            session['apellido']  = usuario.apellido
            return redirect(url_for('login'))
        else:
            flash("Credenciales inválidas", "danger")
            return redirect(url_for('login'))

    # 3) Si es GET y no hay sesión, muestra el formulario
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('rol_id', None)
    session.pop('carrito', None)  # Vaciar el carrito
    flash("Sesión cerrada", "info")
    return redirect(url_for('login'))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Verifica que exista el rol en sesión y que sea 1 (Admin)
        if 'rol_id' not in session or int(session['rol_id']) != 1:
            flash("Acceso no autorizado", "danger")
            # Redirige a una ruta permitida, por ejemplo, a listar productos
            return redirect(url_for('listar_productos'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
@admin_required
def inicio():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    hoy = datetime.today()
    mes_actual = hoy.month
    anio_actual = hoy.year
    user_id = session.get('user_id')

    total_general = (
        db.session
          .query(func.coalesce(func.sum(Venta.total), 0.0))
          .filter(
            extract('year',  Venta.fecha) == anio_actual,
            extract('month', Venta.fecha) == mes_actual
          )
          .scalar()
    )

    total_usuario = (
        db.session
          .query(func.coalesce(func.sum(Venta.total), 0.0))
          .filter(
            extract('year',  Venta.fecha) == anio_actual,
            extract('month', Venta.fecha) == mes_actual,
            Venta.usuario_id == user_id
          )
          .scalar()
    )

    total_general_fmt = f"{int(total_general):,}".replace(",", ".")
    total_usuario_fmt = f"{int(total_usuario):,}".replace(",", ".")

    # Nombre del mes en español
    MESES_ES = {
        1: 'Enero',   2: 'Febrero',  3: 'Marzo',      4: 'Abril',
        5: 'Mayo',    6: 'Junio',    7: 'Julio',      8: 'Agosto',
        9: 'Septiembre', 10: 'Octubre', 11: 'Noviembre', 12: 'Diciembre'
    }
    nombre_mes_es = MESES_ES[mes_actual]

    productos_criticos = Producto.query.filter(
        Producto.stock <= 10
    ).order_by(Producto.nombre.asc()).all()
    
    return render_template('index.html',
        nombre_mes=nombre_mes_es,
        anio_actual=anio_actual,
        total_general=total_general_fmt,
        total_usuario=total_usuario_fmt,
        productos_criticos=productos_criticos
    )

def generar_codigo_automatico():
    # 1) Recogemos los códigos numéricos de los auto-generados
    auto_prods = Producto.query.filter_by(tiene_codigo=False).all()
    auto_codes = [int(p.codigo) for p in auto_prods if str(p.codigo).isdigit()]
    # 2) Calculamos el siguiente correlativo puro
    next_code = max(auto_codes, default=0) + 1

    # 3) Recogemos los códigos numéricos de los manuales para evitar colisiones
    manual_prods = Producto.query.filter_by(tiene_codigo=True).all()
    manual_codes = {int(p.codigo) for p in manual_prods if str(p.codigo).isdigit()}

    # 4) Si el correlativo choca con alguno manual, lo saltamos
    while next_code in manual_codes:
        next_code += 1

    return str(next_code)

@app.route('/agregar', methods=['GET', 'POST'])
@admin_required
def agregar_producto():
    if request.method == 'POST':
        no_codigo = request.form.get('no_codigo')
        if no_codigo:
            # Producto sin código manual; se genera automático
            codigo = generar_codigo_automatico()
            tiene_codigo = False
        else:
            codigo = str(request.form['codigo']).strip()
            tiene_codigo = True
        
        nombre = request.form['nombre']
        precio = request.form['precio']
        stock = request.form['stock']
        
        # Validar que precio y stock sean válidos y mayores a 0
        try:
            precio_val = float(precio)
            stock_val = int(stock)
        except ValueError:
            flash('El precio y el stock deben ser valores numéricos válidos.', 'danger')
            return redirect(url_for('agregar_producto'))
        
        if precio_val <= 0 or stock_val <= 0:
            flash('El precio y el stock deben ser mayores a 0.', 'danger')
            return redirect(url_for('agregar_producto'))
        
        # Si se ingresó el código manualmente, se verifica que no exista
        if tiene_codigo and Producto.query.filter_by(codigo=codigo).first():
            flash('El código de barra ya existe', 'danger')
            return redirect(url_for('agregar_producto'))
        
        # Por seguridad, si se genera automáticamente, se verifica también
        if not tiene_codigo and Producto.query.filter_by(codigo=codigo).first():
            flash('Error al generar el código automáticamente, por favor intente nuevamente.', 'danger')
            return redirect(url_for('agregar_producto'))
        
        producto = Producto(
            codigo=codigo,
            nombre=nombre,
            precio=precio_val,
            stock=stock_val,
            tiene_codigo=tiene_codigo
        )
        db.session.add(producto)
        db.session.commit()
        flash('Producto agregado correctamente', 'success')
        return redirect(url_for('listar_productos'))
    return render_template('agregar.html')

@app.route('/listar')
def listar_productos():
    productos = Producto.query.all()
    productos_con_codigo = [p for p in productos if p.tiene_codigo]
    productos_sin_codigo = [p for p in productos if not p.tiene_codigo]
    return render_template('listar.html', productos_con_codigo=productos_con_codigo, productos_sin_codigo=productos_sin_codigo)


@app.template_filter('formato_precio')
def formato_precio(value):
    try:
        # Convertir a número, formatear con separador de miles (coma) y sin decimales,
        # luego se reemplazan las comas por puntos para adaptarse al formato deseado.
        return f"{float(value):,.0f}".replace(",", ".")
    except (ValueError, TypeError):
        return value

@app.route('/ventas', methods=['GET', 'POST'])
def ventas():
    # Aseguramos que 'carrito' se guarde en sesión como diccionario para agrupar productos
    if 'carrito' not in session or not isinstance(session['carrito'], dict):
        session['carrito'] = {}
    carrito = session['carrito']

    if request.method == 'POST':
        action = request.form.get('action')
        codigo_input = request.form.get('codigo')
        # Forzamos a que el código sea una cadena limpia:
        codigo_key = str(codigo_input).strip()
        try:
            cantidad = int(request.form.get('cantidad', 1))
        except ValueError:
            flash('Cantidad inválida', 'danger')
            return redirect(url_for('ventas'))
        
        if action == 'agregar':
            producto = Producto.query.filter_by(codigo=codigo_key).first()
            if not producto:
                flash('Producto no encontrado', 'danger')
                return redirect(url_for('ventas'))
            # Validar que la cantidad a agregar (sumada a la que ya está en el carrito) no exceda el stock
            cantidad_actual = carrito[codigo_key]['cantidad'] if codigo_key in carrito else 0
            if (cantidad_actual + cantidad) > producto.stock:
                flash('No puede agregar más unidades de este producto, excede el stock disponible.', 'warning')
                return redirect(url_for('ventas'))
            
            # Si el producto ya está en el carrito, se suma la cantidad; de lo contrario, se agrega
            if codigo_key in carrito:
                carrito[codigo_key]['cantidad'] += cantidad
            else:
                carrito[codigo_key] = {
                    'nombre': producto.nombre,
                    'precio': producto.precio,
                    'cantidad': cantidad
                }
            flash('Producto agregado al carrito', 'success')

        elif action == 'finalizar':
            # Validar nuevamente que cada producto del carrito tenga suficiente stock
            for codigo, datos in carrito.items():
                producto = Producto.query.filter_by(codigo=codigo).first()
                if not producto or datos['cantidad'] > producto.stock:
                    flash(f'Stock insuficiente para el producto {codigo}.', 'danger')
                    return redirect(url_for('ventas'))
            # Actualizar stock: descontar la cantidad vendida por cada producto
            for codigo, datos in carrito.items():
                producto = Producto.query.filter_by(codigo=codigo).first()
                producto.stock -= datos['cantidad']
            # Crear la venta en la base de datos
            detalles = json.dumps(carrito)
            total = sum(datos['cantidad'] * datos['precio'] for datos in carrito.values())
            venta = Venta(total=total, detalles=detalles)
            # Asigna el usuario que realiza la venta usando la variable de sesión
            venta.usuario_id = session.get('user_id')
            db.session.add(venta)
            db.session.commit()
            flash('Venta guardada exitosamente', 'success')
            carrito = {}

        elif action == 'vaciar':
            carrito = {}
            flash('Carrito vaciado correctamente', 'info')

        session['carrito'] = carrito
        session.modified = True
        return redirect(url_for('ventas'))

    # Preparar la lista y calcular totales
    carrito_lista = []
    total = 0
    for codigo, datos in carrito.items():
        subtotal = datos['cantidad'] * datos['precio']
        total += subtotal
        carrito_lista.append({
            'codigo': codigo,
            'nombre': datos['nombre'],
            'precio': datos['precio'],
            'cantidad': datos['cantidad'],
            'subtotal': subtotal
        })

    return render_template('ventas.html', carrito=carrito_lista, total=total)

@app.route('/eliminar_del_carrito/<codigo>', methods=['POST'])
def eliminar_del_carrito(codigo):
    carrito = session.get('carrito', {})
    # Forzamos que el código se compare como cadena sin espacios
    codigo_key = str(codigo).strip()
    if codigo_key in carrito:
        if carrito[codigo_key]['cantidad'] > 1:
            carrito[codigo_key]['cantidad'] -= 1
        else:
            del carrito[codigo_key]
    session['carrito'] = carrito
    session.modified = True
    flash('Producto eliminado del carrito', 'info')
    return redirect(url_for('ventas'))

@app.route('/agregar_al_carrito/<codigo>', methods=['POST'])
def agregar_al_carrito(codigo):
    # Aseguramos que el carrito se maneje como un diccionario
    carrito = session.get('carrito', {})
    codigo_key = str(codigo).strip()
    if codigo_key in carrito:
        # Obtener el producto desde la base de datos para conocer el stock real
        producto = Producto.query.filter_by(codigo=codigo_key).first()
        if not producto:
            flash('Producto no encontrado', 'danger')
            return redirect(url_for('ventas'))
        # Validar que al agregar una unidad más no se exceda el stock
        if carrito[codigo_key]['cantidad'] + 1 > producto.stock:
            flash('No se puede agregar más unidades, stock excedido.', 'warning')
        else:
            carrito[codigo_key]['cantidad'] += 1
            flash('Se agregó una unidad al producto', 'success')
    else:
        flash('El producto no está en el carrito', 'warning')
    session['carrito'] = carrito
    session.modified = True
    return redirect(url_for('ventas'))


@app.route('/vaciar_carrito', methods=['POST'])
def vaciar_carrito():
    session['carrito'] = []
    session.modified = True
    flash('Carrito vaciado correctamente', 'info')
    return redirect(url_for('ventas'))

@app.route('/ventas_realizadas')
def ventas_realizadas():
    # Verifica que el usuario esté logueado
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Si el usuario es vendedor (rol 2), filtrar las ventas por el usuario actual.
    if int(session.get('rol_id', 0)) == 2:
        ventas = Venta.query.filter_by(usuario_id=session.get('user_id')).order_by(Venta.fecha.desc()).all()
    else:
        ventas = Venta.query.order_by(Venta.fecha.desc()).all()
    
    # Agrupar las ventas por fecha (formato 'YYYY-MM-DD') y parsear el JSON de detalles
    ventas_por_fecha = {}
    for venta in ventas:
        fecha_str = venta.fecha.strftime('%Y-%m-%d')
        try:
            detalle_items = json.loads(venta.detalles)
        except Exception:
            detalle_items = {}
        venta.detalle_items = detalle_items

        if fecha_str not in ventas_por_fecha:
            ventas_por_fecha[fecha_str] = []
        ventas_por_fecha[fecha_str].append(venta)
    
    return render_template('ventas_realizadas.html', ventas_por_fecha=ventas_por_fecha)

    
    return render_template('ventas_realizadas.html', ventas_por_fecha=ventas_por_fecha)

@app.route('/editar/<int:id>', methods=['GET', 'POST'])
@admin_required
def editar_producto(id):
    producto = Producto.query.get_or_404(id)
    if request.method == 'POST':
        nombre = request.form['nombre']
        precio = request.form['precio']
        stock = request.form['stock']

        # Validación: convertir a número y verificar que sean mayores a 0
        try:
            precio_val = float(precio)
            stock_val = int(stock)
        except ValueError:
            flash('El precio y el stock deben ser valores numéricos válidos.', 'danger')
            return redirect(url_for('editar_producto', id=id))
        
        if precio_val <= 0 or stock_val <= 0:
            flash('El precio y el stock deben ser mayores a 0.', 'danger')
            return redirect(url_for('editar_producto', id=id))
        
        # Actualizamos solo los campos permitidos
        producto.nombre = nombre
        producto.precio = precio_val
        producto.stock = stock_val
        db.session.commit()
        flash('Producto actualizado correctamente', 'success')
        return redirect(url_for('listar_productos'))
        
    return render_template('editar.html', producto=producto)

# @app.route('/eliminar/<int:id>', methods=['POST'])
# @admin_required
# def eliminar_producto(id):
#     producto = Producto.query.get_or_404(id)
#     # La eliminación del producto no afecta las ventas ya realizadas
#     db.session.delete(producto)
#     db.session.commit()
#     flash('Producto eliminado correctamente', 'info')
#     return redirect(url_for('listar_productos'))

@app.route('/eliminar_producto/<int:id>', methods=['POST'])
@admin_required
def eliminar_producto(id):
    # 1) comprobación idéntica
    ventas = Venta.query.all()
    for v in ventas:
        detalles = json.loads(v.detalles or '{}')
        if str(id) in detalles:
            flash('No se puede eliminar este producto porque tiene ventas asociadas.', 'danger')
            return redirect(url_for('listar_productos'))

    # 2) si pasó la validación, borramos
    producto = Producto.query.get_or_404(id)
    db.session.delete(producto)
    db.session.commit()
    flash('Producto eliminado correctamente.', 'success')
    return redirect(url_for('listar_productos'))

@app.route('/producto/<int:id>/tiene_ventas')
def producto_tiene_ventas(id):
    # Recorremos todas las ventas y chequeamos su campo `detalles` (JSON en texto)
    ventas = Venta.query.all()
    for v in ventas:
        detalles = json.loads(v.detalles or '{}')
        if str(id) in detalles:
            return jsonify({'tiene_ventas': True})
    return jsonify({'tiene_ventas': False})

def generate_unique_username(base_username):
    username = base_username
    counter = 1
    # Mientras exista un usuario con ese username, se añade un número al final
    while Usuario.query.filter_by(username=username).first():
        username = f"{base_username}{counter}"
        counter += 1
    return username

@app.route('/crear_usuario', methods=['GET', 'POST'])
@admin_required
def crear_usuario():
    if request.method == 'POST':
        nombre = request.form['nombre'].strip()
        apellido = request.form['apellido'].strip()
        password = request.form['password']
        reingresar_password = request.form['reingresar_password']
        rol_id = request.form['rol']  # Se recibirá un valor ("1" o "2")
        
        # Validaciones básicas
        if not nombre or not apellido or not password:
            flash('Todos los campos son requeridos.', 'danger')
            return redirect(url_for('crear_usuario'))
        
        if password != reingresar_password:
            flash('Las contraseñas no coinciden.', 'danger')
            return redirect(url_for('crear_usuario'))
        
        # Si se agrega el mismo nombre y apellido, no se debe crear el usuario.
        existing_user = Usuario.query.filter_by(nombre=nombre, apellido=apellido).first()
        if existing_user:
            flash('Ya existe un usuario con el mismo nombre y apellido.', 'danger')
            return redirect(url_for('crear_usuario'))
        
        # Generar username base: primera letra del nombre + apellido en minúsculas.
        base_username = (nombre[0] + apellido).lower()
        # Genera un username único agregando un número si fuera necesario.
        username = generate_unique_username(base_username)
        
        # Crear el usuario y guardarlo en la base de datos
        nuevo_usuario = Usuario(
            nombre=nombre,
            apellido=apellido,
            username=username,
            password=password,  # En producción, se debe utilizar hash para la contraseña.
            rol_id=int(rol_id)
        )
        db.session.add(nuevo_usuario)
        db.session.commit()
        flash(f'Usuario creado exitosamente. Username asignado: {username}', 'success')
        return redirect(url_for('crear_usuario'))
    
    return render_template('crear_usuario.html')

# Listar usuarios
@app.route('/listar_usuarios')
@admin_required
def listar_usuarios():
    usuarios = Usuario.query.all()
    return render_template('listar_usuarios.html', usuarios=usuarios)

@app.route('/editar_usuario/<int:id>', methods=['GET', 'POST'])
@admin_required
def editar_usuario(id):
    usuario = Usuario.query.get_or_404(id)

    if request.method == 'POST':
        # 1) Leer form
        nombre   = request.form['nombre'].strip()
        apellido = request.form['apellido'].strip()
        password = request.form['password'].strip()
        rol      = request.form['rol']

        # 2) Validar
        if not nombre or not apellido or not password:
            flash('Todos los campos son obligatorios.', 'danger')
            return redirect(url_for('editar_usuario', id=id))

        # 3) Guardamos valores actuales para comparar
        old_nombre   = usuario.nombre
        old_apellido = usuario.apellido

        # 4) Actualizamos campos
        usuario.nombre   = nombre
        usuario.apellido = apellido
        usuario.password = password   # recuerda hashear en prod
        usuario.rol_id   = int(rol)

        # 5) Sólo regenerar username si cambió nombre o apellido
        if nombre != old_nombre or apellido != old_apellido:
            base_username = (nombre[0] + apellido).lower()
            usuario.username = generate_unique_username(base_username)

        # 6) Commit y feedback
        try:
            db.session.commit()
            flash('Usuario actualizado correctamente.', 'success')
        except IntegrityError: # type: ignore
            db.session.rollback()
            flash('El username generado ya existe. Intenta con otro nombre/apellido.', 'danger')
            return redirect(url_for('editar_usuario', id=id))

        return redirect(url_for('listar_usuarios'))

    # GET
    return render_template('listar_usuarios.html', usuario=usuario)


# Eliminar usuario
@app.route('/eliminar_usuario/<int:id>', methods=['POST'])
@admin_required
def eliminar_usuario(id):
    usuario = Usuario.query.get_or_404(id)
    db.session.delete(usuario)
    db.session.commit()
    flash('Usuario eliminado correctamente.', 'info')
    return redirect(url_for('listar_usuarios'))

@app.route('/autocomplete')
def autocomplete():
    q = request.args.get('q', '').strip()
    if not q:
        return jsonify([])

    # Filtrar productos que coincidan en nombre o código (usando ILIKE para ignorar mayúsc/minúsc).
    # En SQLite podrías usar .filter(Producto.nombre.like(f"%{q}%")) si no soporta ILIKE nativamente.
    # Ejemplo genérico:
    productos = Producto.query.filter(
        db.or_(
            Producto.nombre.ilike(f"%{q}%"),
            Producto.codigo.ilike(f"%{q}%")
        )
    ).all()

    # Formar respuesta en JSON con datos básicos
    resultados = []
    for p in productos:
        resultados.append({
            "id": p.id,
            "nombre": p.nombre,
            "codigo": p.codigo
        })
    return jsonify(resultados)

@app.template_filter('santiago_time')
def santiago_time(dt):
    # Si dt es naive, asumimos que está en UTC
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=zoneinfo.ZoneInfo("UTC"))
    # Convertir a la zona horaria de Santiago, Chile
    santiago_tz = zoneinfo.ZoneInfo("America/Santiago")
    return dt.astimezone(santiago_tz).strftime("%H:%M:%S")

@app.route('/ventas_calendario')
def ventas_calendario():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if int(session.get('rol_id', 0)) == 2:
        ventas = Venta.query.filter_by(usuario_id=session.get('user_id')).order_by(Venta.fecha.desc()).all()
    else:
        ventas = Venta.query.order_by(Venta.fecha.desc()).all()
    
    calendar_data = {}
    for venta in ventas:
        fecha_str = venta.fecha.strftime('%Y-%m-%d')
        try:
            detalle_items = json.loads(venta.detalles)
        except Exception:
            detalle_items = {}
        sale_data = {
            'id': venta.id,
            'total': venta.total,
            'hora': venta.fecha.strftime('%H:%M:%S'),
            'usuario': {
                'nombre': venta.usuario.nombre,
                'apellido': venta.usuario.apellido
            } if venta.usuario else None,
            'detalle_items': detalle_items  # Agregamos el detalle de la venta
        }
        if fecha_str not in calendar_data:
            calendar_data[fecha_str] = []
        calendar_data[fecha_str].append(sale_data)
    
    return render_template('ventas_calendario.html', calendar_data=calendar_data)

@app.route('/productos_mas_vendidos')
def productos_mas_vendidos():
    # Obtener el límite (cantidad de productos a mostrar) desde un parámetro GET; por defecto, 10
    try:
        limit = int(request.args.get("limit", 10))
    except ValueError:
        limit = 10

    # Recuperar todas las ventas
    ventas = Venta.query.all()

    # Diccionario para agrupar ventas por mes-año:
    # { "YYYY-MM": { código_producto: { 'nombre': ..., 'cantidad': int, 'monto_total': float } } }
    data = {}
    for venta in ventas:
        grupo = venta.fecha.strftime('%Y-%m')
        if grupo not in data:
            data[grupo] = {}
        try:
            detalles = json.loads(venta.detalles)
        except Exception:
            detalles = {}
        for cod, info in detalles.items():
            if cod not in data[grupo]:
                data[grupo][cod] = {
                    'nombre': info.get('nombre', 'Producto sin nombre'),
                    'cantidad': 0,
                    'monto_total': 0.0
                }
            try:
                cantidad = int(info.get('cantidad', 0))
            except Exception:
                cantidad = 0
            try:
                precio = float(info.get('precio', 0))
            except Exception:
                precio = 0.0
            data[grupo][cod]['cantidad'] += cantidad
            data[grupo][cod]['monto_total'] += precio * cantidad

    # Para cada grupo, ordenar los productos de mayor a menor según la cantidad vendida y limitar la cantidad mostrada
    resultados = {}
    for grupo, productos in data.items():
        productos_ordenados = sorted(productos.items(), key=lambda x: x[1]['cantidad'], reverse=True)
        resultados[grupo] = productos_ordenados[:limit]

    return render_template('productos_mas_vendidos.html', resultados=resultados, limit=limit)

@app.route('/productos_bajo_stock')
def productos_bajo_stock():
    # Se seleccionan los productos con stock menor o igual a 10
    productos = Producto.query.filter(Producto.stock <= 10).filter(Producto.stock > 0).all()
    # Separar en dos listas: Stock Bajo (< 5) y Stock Medio (entre 5 y 10 inclusive)
    stock_bajo = [p for p in productos if p.stock < 5]
    stock_medio = [p for p in productos if 5 <= p.stock <= 10]
    return render_template('productos_bajo_stock.html', stock_bajo=stock_bajo, stock_medio=stock_medio)

@app.template_filter('formato_precio')
def formato_precio(value):
    try:
        # Formatea el valor: separador de miles con coma, sin decimales.
        # Luego reemplazamos la coma por punto.
        return f"{float(value):,.0f}".replace(',', '.')
    except (ValueError, TypeError):
        return value

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Crear el usuario admin por defecto si no existe
        admin = Usuario.query.filter_by(username='admin').first()
        if not admin:
            admin = Usuario(
                nombre="admin",
                apellido="admin",
                username="admin",
                password="kvM7nIYblg1IMK2",  # En producción, se debe guardar un hash
                rol_id=1
            )
            db.session.add(admin)
            db.session.commit()
    app.run(debug=True)