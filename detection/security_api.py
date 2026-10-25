"""Dashboard evidence and administrator-only simulated response controls."""
from flask import Blueprint,jsonify,request
from router.control_api import admin_required
from router.write_safety import locked
from detection.evidence_store import current_security
from response import policy
from simulation import viva_lab

security=Blueprint('security_pipeline',__name__)

@security.errorhandler(ValueError)
def invalid(error):return jsonify(status='error',message=str(error)),400

@security.get('/api/security')
def status():
    ident=request.args.get('device_id',type=int)
    return jsonify(**current_security(ident),policy=policy.settings(),physical_writes_locked=locked(),automatic_physical_enforcement=False)

@security.post('/api/security/policy')
@admin_required
def configure():
    data=request.get_json(silent=True)
    if not isinstance(data,dict) or data.pop('confirmed',False) is not True:raise ValueError('Explicit policy confirmation required')
    return jsonify(status='success',policy=policy.set_settings(data),physical_router_writes=0)

@security.get('/api/security/viva')
def viva_status():return jsonify(viva_lab.status())

@security.post('/api/security/viva/run')
@admin_required
def viva_run():
    data=request.get_json(silent=True) or {}
    if not isinstance(data,dict):raise ValueError('A structured replay request is required')
    return jsonify(status='success',**viva_lab.run(data.get('scenario')))

@security.post('/api/security/viva/reset')
@admin_required
def viva_reset():return jsonify(status='success',**viva_lab.reset())

@security.post('/api/security/viva/release')
@admin_required
def viva_release():
    data=request.get_json(silent=True) or {}
    if not isinstance(data,dict):raise ValueError('A structured release request is required')
    if type(data.get('decision_id')) is not int:raise ValueError('A simulated decision ID is required')
    return jsonify(status='success',**viva_lab.release(data['decision_id']))
