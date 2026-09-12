import os, base64, secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import jwt
from fastapi import FastAPI, HTTPException, Request, Response, Depends
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy import create_engine, text
from passlib.hash import argon2

BASE = Path(__file__).resolve().parent
STATIC = BASE / 'static'
DATABASE_URL = os.environ.get('DATABASE_URL')
SECRET_KEY = os.environ.get('SECRET_KEY')
COOKIE_SECURE = os.environ.get('COOKIE_SECURE', 'false').lower() == 'true'
if not DATABASE_URL or not SECRET_KEY:
    raise RuntimeError('DATABASE_URL and SECRET_KEY are required')

engine = create_engine(DATABASE_URL, pool_pre_ping=True, pool_recycle=1800)
app = FastAPI(title='Arthroplasty Registry Cloud', version='1.0.0')
app.mount('/static', StaticFiles(directory=str(STATIC)), name='static')

class LoginIn(BaseModel):
    username: str
    password: str

class UserIn(BaseModel):
    username: str
    password: str
    full_name: str
    role: str = 'data_entry'

class RecordIn(BaseModel):
    id: Optional[str] = None
    record: dict

class ImageIn(BaseModel):
    key: str
    registry_id: str
    section: str
    data_url: str


def init_db():
    migration = (BASE.parent / 'db' / 'migrations' / '001_initial.sql').read_text()
    with engine.begin() as c:
        for stmt in [x.strip() for x in migration.split(';') if x.strip()]:
            c.execute(text(stmt))
        username = os.getenv('BOOTSTRAP_ADMIN_USERNAME')
        password = os.getenv('BOOTSTRAP_ADMIN_PASSWORD')
        name = os.getenv('BOOTSTRAP_ADMIN_NAME', 'Registry Administrator')
        if username and password:
            exists = c.execute(text('SELECT 1 FROM users WHERE username=:u'), {'u': username}).scalar()
            if not exists:
                c.execute(text('INSERT INTO users(username,full_name,role,password_hash) VALUES (:u,:n,\'admin\',:p)'), {'u':username,'n':name,'p':argon2.hash(password)})

@app.on_event('startup')
def startup():
    init_db()


def token_for(user):
    now = datetime.now(timezone.utc)
    payload = {'sub': str(user['user_id']), 'username': user['username'], 'role': user['role'], 'exp': now + timedelta(hours=12)}
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')


def current_user(request: Request):
    tok = request.cookies.get('registry_session')
    if not tok:
        raise HTTPException(401, 'Not authenticated')
    try:
        p = jwt.decode(tok, SECRET_KEY, algorithms=['HS256'])
    except jwt.PyJWTError:
        raise HTTPException(401, 'Session expired')
    with engine.begin() as c:
        row = c.execute(text('SELECT user_id,username,full_name,role,is_active FROM users WHERE user_id=:id'), {'id': int(p['sub'])}).mappings().first()
    if not row or not row['is_active']:
        raise HTTPException(401, 'Account inactive')
    return dict(row)


def admin_only(user=Depends(current_user)):
    if user['role'] != 'admin': raise HTTPException(403, 'Administrator access required')
    return user

@app.get('/')
def index():
    return FileResponse(STATIC / 'index.html')

@app.get('/healthz')
def healthz():
    with engine.begin() as c: c.execute(text('SELECT 1'))
    return {'status':'ok','database':'ok','version':'1.0.0'}

@app.post('/api/login')
def login(data: LoginIn, response: Response):
    with engine.begin() as c:
        row = c.execute(text('SELECT * FROM users WHERE username=:u AND is_active=true'), {'u':data.username.strip()}).mappings().first()
    if not row or not argon2.verify(data.password, row['password_hash']):
        raise HTTPException(401, 'Invalid username or password')
    response.set_cookie('registry_session', token_for(row), httponly=True, secure=COOKIE_SECURE, samesite='lax', max_age=43200, path='/')
    return {'user': {'name':row['full_name'], 'username':row['username'], 'role':row['role']}}

@app.post('/api/logout')
def logout(response: Response):
    response.delete_cookie('registry_session', path='/')
    return {'ok':True}

@app.get('/api/me')
def me(user=Depends(current_user)):
    return {'user': {'name':user['full_name'],'username':user['username'],'role':user['role']}}

@app.get('/api/records')
def records(user=Depends(current_user)):
    with engine.begin() as c:
        rows = c.execute(text("SELECT record FROM registry_records ORDER BY (record->>'surgeryDate') DESC NULLS LAST, record_id DESC"), {}).mappings().all()
    return [r['record'] for r in rows]

@app.get('/api/records/{registry_id}')
def get_record(registry_id: str, user=Depends(current_user)):
    with engine.begin() as c:
        row = c.execute(text('SELECT record FROM registry_records WHERE registry_id=:id'), {'id':registry_id}).mappings().first()
    if not row: raise HTTPException(404,'Record not found')
    return row['record']

@app.post('/api/records')
def create_record(data: RecordIn, user=Depends(current_user)):
    rec = dict(data.record)
    rid = rec.get('id') or ('P-' + secrets.token_hex(4).upper())
    rec['id'] = rid
    with engine.begin() as c:
        exists = c.execute(text('SELECT 1 FROM registry_records WHERE registry_id=:id'), {'id':rid}).scalar()
        if exists: raise HTTPException(409,'Registry ID already exists')
        c.execute(text('''INSERT INTO registry_records(registry_id,mrn,record,created_by) VALUES (:id,:mrn,CAST(:record AS jsonb),:uid)'''), {'id':rid,'mrn':rec.get('mrn'),'record':__import__('json').dumps(rec),'uid':user['user_id']})
        audit(c,user,'created','registry_records',rid,{'mrn':rec.get('mrn')})
    return rec

@app.put('/api/records/{registry_id}')
def update_record(registry_id: str, data: RecordIn, user=Depends(current_user)):
    rec = dict(data.record); rec['id'] = registry_id
    with engine.begin() as c:
        exists = c.execute(text('SELECT 1 FROM registry_records WHERE registry_id=:id'), {'id':registry_id}).scalar()
        if not exists: raise HTTPException(404,'Record not found')
        c.execute(text('''UPDATE registry_records SET mrn=:mrn, record=CAST(:record AS jsonb), updated_at=NOW() WHERE registry_id=:id'''), {'id':registry_id,'mrn':rec.get('mrn'),'record':__import__('json').dumps(rec)})
        audit(c,user,'edited','registry_records',registry_id,{'mrn':rec.get('mrn')})
    return rec

@app.delete('/api/records/{registry_id}')
def delete_record(registry_id: str, user=Depends(admin_only)):
    with engine.begin() as c:
        res = c.execute(text('DELETE FROM registry_records WHERE registry_id=:id'), {'id':registry_id})
        if res.rowcount == 0: raise HTTPException(404,'Record not found')
        audit(c,user,'deleted','registry_records',registry_id,{})
    return {'ok':True}

@app.get('/api/activity')
def activity(user=Depends(current_user)):
    with engine.begin() as c:
        rows=c.execute(text('''SELECT a.timestamp,a.action,a.record_id,a.details,u.full_name FROM audit_log a LEFT JOIN users u ON u.user_id=a.user_id ORDER BY a.timestamp DESC LIMIT 2000''')).mappings().all()
    return [{'user':r['full_name'] or 'Unknown','action':r['action'],'patientId':r['record_id'],'at':r['timestamp'].isoformat(),'details':r['details']} for r in rows]

def audit(c,user,action,table_name,record_id,details):
    import json
    c.execute(text('INSERT INTO audit_log(user_id,action,table_name,record_id,details) VALUES (:u,:a,:t,:r,CAST(:d AS jsonb))'), {'u':user['user_id'],'a':action,'t':table_name,'r':record_id,'d':json.dumps(details)})

@app.get('/api/images')
def image_list(registry_id: str, user=Depends(current_user)):
    with engine.begin() as c:
        rows=c.execute(text('SELECT image_key,section FROM images WHERE registry_id=:id ORDER BY image_id'), {'id':registry_id}).mappings().all()
    return [{'key':r['image_key'],'section':r['section']} for r in rows]

@app.get('/api/images/{image_key}')
def image_get(image_key: str, user=Depends(current_user)):
    with engine.begin() as c:
        row=c.execute(text('SELECT image_data,mime_type FROM images WHERE image_key=:k'), {'k':image_key}).mappings().first()
    if not row: raise HTTPException(404,'Image not found')
    return Response(content=bytes(row['image_data']), media_type=row['mime_type'], headers={'Cache-Control':'private, max-age=3600'})

@app.post('/api/images')
def image_create(data: ImageIn, user=Depends(current_user)):
    if data.section not in ('preop','postop'): raise HTTPException(400,'Invalid section')
    if not data.data_url.startswith('data:image/') or ',' not in data.data_url: raise HTTPException(400,'Invalid image data')
    head,b64=data.data_url.split(',',1)
    mime=head.split(';')[0].split(':',1)[1]
    raw=base64.b64decode(b64)
    if len(raw)>8*1024*1024: raise HTTPException(413,'Image exceeds 8MB')
    with engine.begin() as c:
        exists=c.execute(text('SELECT 1 FROM registry_records WHERE registry_id=:id'), {'id':data.registry_id}).scalar()
        if not exists: raise HTTPException(404,'Record not found')
        c.execute(text('INSERT INTO images(image_key,registry_id,section,mime_type,image_data,created_by) VALUES (:k,:r,:s,:m,:d,:u) ON CONFLICT(image_key) DO UPDATE SET image_data=EXCLUDED.image_data'), {'k':data.key,'r':data.registry_id,'s':data.section,'m':mime,'d':raw,'u':user['user_id']})
    return {'key':data.key}

@app.delete('/api/images/{image_key}')
def image_delete(image_key: str, user=Depends(current_user)):
    with engine.begin() as c: c.execute(text('DELETE FROM images WHERE image_key=:k'), {'k':image_key})
    return {'ok':True}

@app.get('/api/users')
def list_users(user=Depends(admin_only)):
    with engine.begin() as c:
        rows=c.execute(text('SELECT user_id,username,full_name,role,is_active,created_at FROM users ORDER BY user_id')).mappings().all()
    return [dict(r) for r in rows]

@app.post('/api/users')
def create_user(data: UserIn, user=Depends(admin_only)):
    if data.role not in ('data_entry','admin','surgeon'): raise HTTPException(400,'Invalid role')
    with engine.begin() as c:
        try:
            row=c.execute(text('INSERT INTO users(username,full_name,role,password_hash) VALUES (:u,:n,:r,:p) RETURNING user_id,username,full_name,role,is_active,created_at'), {'u':data.username.strip(),'n':data.full_name.strip(),'r':data.role,'p':argon2.hash(data.password)}).mappings().first()
        except Exception as e: raise HTTPException(409,'Username already exists')
    return dict(row)

@app.post('/api/users/{user_id}/disable')
def disable_user(user_id:int, user=Depends(admin_only)):
    if user_id == user['user_id']: raise HTTPException(400,'Cannot disable your own account')
    with engine.begin() as c: c.execute(text('UPDATE users SET is_active=false WHERE user_id=:id'), {'id':user_id})
    return {'ok':True}
