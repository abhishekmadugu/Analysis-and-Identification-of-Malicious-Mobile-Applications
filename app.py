#!/usr/bin/env python3
"""
APK Malware Scanner - Flask Backend
Real APK analysis using Androguard and YARA
"""

import os
import json
import hashlib
import tempfile
import traceback
from datetime import datetime
from pathlib import Path

from flask import Flask, request, jsonify, render_template, send_from_directory
from flask_cors import CORS
from werkzeug.utils import secure_filename

try:
    # Use Androguard 4.x API
    from androguard.core.apk import APK
    from androguard.misc import AnalyzeAPK, AnalyzeDex
    ANDROGUARD_AVAILABLE = True
    ANDROGUARD_VERSION = "4.x"
    print("Using Androguard 4.x API")
except ImportError:
    try:
        # Fallback to older versions
        from androguard.core.bytecodes.apk import APK
        from androguard.core.analysis.analysis import Analysis
        from androguard.core.bytecodes.dvm import DalvikVMFormat
        ANDROGUARD_AVAILABLE = True
        ANDROGUARD_VERSION = "3.x"
        print("Using Androguard 3.x API")
    except ImportError:
        print("Warning: Androguard not installed. APK analysis will be limited.")
        ANDROGUARD_AVAILABLE = False
        ANDROGUARD_VERSION = None

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    print("Warning: YARA not installed. Malware detection will be disabled.")
    YARA_AVAILABLE = False

app = Flask(__name__)
CORS(app)

# Configuration
UPLOAD_FOLDER = 'uploads'
YARA_RULES_FOLDER = 'yara_rules'
ALLOWED_EXTENSIONS = {'apk'}
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

# Ensure upload directory exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_file_hashes(file_path):
    """Calculate MD5 and SHA1 hashes of a file"""
    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()
    
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            md5_hash.update(chunk)
            sha1_hash.update(chunk)
            sha256_hash.update(chunk)
    
    return {
        'md5': md5_hash.hexdigest(),
        'sha1': sha1_hash.hexdigest(),
        'sha256': sha256_hash.hexdigest()
    }

def analyze_permissions(permissions):
    """Categorize Android permissions by risk level"""
    high_risk_permissions = {
        'android.permission.SEND_SMS': 'Can send SMS messages (potential premium rate fraud)',
        'android.permission.READ_SMS': 'Can read SMS messages (privacy concern)',
        'android.permission.RECEIVE_SMS': 'Can intercept SMS messages',
        'android.permission.READ_CONTACTS': 'Can access contact list (privacy concern)',
        'android.permission.READ_CALL_LOG': 'Can read call history (privacy concern)',
        'android.permission.RECORD_AUDIO': 'Can record audio (privacy concern)',
        'android.permission.CAMERA': 'Can access camera (privacy concern)',
        'android.permission.ACCESS_FINE_LOCATION': 'Can access precise location (privacy concern)',
        'android.permission.DEVICE_ADMINISTRATOR': 'Can perform admin operations (potential abuse)',
        'android.permission.BIND_DEVICE_ADMIN': 'Can bind as device administrator',
        'android.permission.SYSTEM_ALERT_WINDOW': 'Can display system overlay windows',
        'android.permission.WRITE_SETTINGS': 'Can modify system settings',
        'android.permission.BIND_ACCESSIBILITY_SERVICE': 'Can access accessibility features',
        'android.permission.BIND_NOTIFICATION_LISTENER_SERVICE': 'Can read notifications'
    }
    
    medium_risk_permissions = {
        'android.permission.ACCESS_COARSE_LOCATION': 'Can access approximate location',
        'android.permission.READ_PHONE_STATE': 'Can read phone state and identity',
        'android.permission.WRITE_EXTERNAL_STORAGE': 'Can write to external storage',
        'android.permission.READ_EXTERNAL_STORAGE': 'Can read external storage',
        'android.permission.WAKE_LOCK': 'Can prevent phone from sleeping',
        'android.permission.VIBRATE': 'Can control vibration',
        'android.permission.GET_ACCOUNTS': 'Can access account list'
    }
    
    categorized = {
        'high_risk': [],
        'medium_risk': [],
        'low_risk': []
    }
    
    for permission in permissions:
        if permission in high_risk_permissions:
            categorized['high_risk'].append({
                'name': permission,
                'description': high_risk_permissions[permission]
            })
        elif permission in medium_risk_permissions:
            categorized['medium_risk'].append({
                'name': permission,
                'description': medium_risk_permissions[permission]
            })
        else:
            categorized['low_risk'].append({
                'name': permission,
                'description': 'Standard permission'
            })
    
    return categorized

def load_yara_rules():
    """Load YARA rules from the yara_rules directory"""
    if not YARA_AVAILABLE:
        return None
    
    yara_files = []
    rules_path = Path(YARA_RULES_FOLDER)
    
    if not rules_path.exists():
        return None
    
    for yar_file in rules_path.glob('*.yar'):
        yara_files.append(str(yar_file))
    
    if not yara_files:
        return None
    
    try:
        # Compile all YARA rules
        rules = yara.compile(filepaths={f'rule_{i}': path for i, path in enumerate(yara_files)})
        return rules
    except Exception as e:
        print(f"Error compiling YARA rules: {e}")
        return None

def scan_with_yara(file_path, rules):
    """Scan file with YARA rules"""
    if not rules:
        return []
    
    try:
        matches = rules.match(file_path)
        threats = []
        
        for match in matches:
            threat = {
                'rule_name': match.rule,
                'tags': match.tags,
                'meta': dict(match.meta) if match.meta else {},
                'strings': [{'identifier': s.identifier, 'instances': len(s.instances)} 
                           for s in match.strings] if match.strings else []
            }
            
            # Extract severity from meta if available
            severity = threat['meta'].get('severity', 'medium')
            threat['severity'] = severity
            
            # Extract description from meta if available
            description = threat['meta'].get('description', f'YARA rule {match.rule} triggered')
            threat['description'] = description
            
            threats.append(threat)
        
        return threats
    except Exception as e:
        print(f"Error scanning with YARA: {e}")
        return []

def analyze_apk(file_path):
    """Analyze APK file using Androguard"""
    if not ANDROGUARD_AVAILABLE:
        return {
            'error': 'Androguard not available',
            'basic_info': {
                'file_size': os.path.getsize(file_path),
                'file_hashes': get_file_hashes(file_path)
            }
        }
    
    try:
        # Load APK
        apk = APK(file_path)
        
        # Basic information
        basic_info = {
            'app_name': apk.get_app_name(),
            'package_name': apk.get_package(),
            'version_name': apk.get_androidversion_name(),
            'version_code': apk.get_androidversion_code(),
            'min_sdk': apk.get_min_sdk_version(),
            'target_sdk': apk.get_target_sdk_version(),
            'file_size': os.path.getsize(file_path),
            'file_hashes': get_file_hashes(file_path)
        }
        
        # Permissions analysis
        permissions = apk.get_permissions()
        permissions_analysis = analyze_permissions(permissions)
        
        # Certificate information
        certificates = []
        try:
            for cert in apk.get_certificates():
                cert_info = {
                    'issuer': cert.issuer.rfc4514_string(),
                    'subject': cert.subject.rfc4514_string(),
                    'serial_number': str(cert.serial_number),
                    'not_valid_before': cert.not_valid_before.isoformat(),
                    'not_valid_after': cert.not_valid_after.isoformat(),
                    'signature_algorithm': cert.signature_algorithm_oid._name,
                    'fingerprint_sha1': cert.fingerprint(hashlib.sha1).hex(),
                    'fingerprint_md5': cert.fingerprint(hashlib.md5).hex(),
                    'is_valid': datetime.now() < cert.not_valid_after
                }
                certificates.append(cert_info)
        except Exception as e:
            print(f"Error extracting certificates: {e}")
        
        # Activities, Services, Receivers
        components = {
            'activities': apk.get_activities(),
            'services': apk.get_services(),
            'receivers': apk.get_receivers(),
            'providers': apk.get_providers()
        }
        
        # Additional analysis for Androguard 4.x
        try:
            if ANDROGUARD_VERSION == "4.x":
                # Use AnalyzeAPK for more comprehensive analysis
                apk_analysis, dalvik_vm, analysis_objects = AnalyzeAPK(file_path)
                
                # Get strings from the APK
                strings = []
                if dalvik_vm:
                    for dvm in dalvik_vm:
                        for string_value in dvm.get_strings():
                            strings.append(string_value.get_value())
                        break  # Only get strings from first DEX file
                
                # Limit strings to prevent memory issues
                if len(strings) > 1000:
                    strings = strings[:1000]
                
                components['strings_sample'] = strings
            else:
                # Fallback for older versions
                components['strings_sample'] = []
                
        except Exception as e:
            print(f"Error in detailed analysis: {e}")
            components['strings_sample'] = []
        
        return {
            'basic_info': basic_info,
            'permissions': permissions_analysis,
            'certificates': certificates,
            'components': components,
            'analysis_timestamp': datetime.now().isoformat()
        }
        
    except Exception as e:
        print(f"Error analyzing APK: {e}")
        traceback.print_exc()
        return {
            'error': f'APK analysis failed: {str(e)}',
            'basic_info': {
                'file_size': os.path.getsize(file_path),
                'file_hashes': get_file_hashes(file_path)
            }
        }

def calculate_risk_score_and_threats(analysis_result, yara_threats):
    """Calculate overall risk score and identify threats based on analysis"""
    score = 0
    detected_threats = []
    
    # Base score
    score += 10
    
    # Get basic info
    basic_info = analysis_result.get('basic_info', {})
    package_name = basic_info.get('package_name', '').lower()
    app_name = basic_info.get('app_name', '').lower()
    
    # Permission-based scoring and threat detection
    permissions = analysis_result.get('permissions', {})
    high_risk_perms = permissions.get('high_risk', [])
    medium_risk_perms = permissions.get('medium_risk', [])
    low_risk_perms = permissions.get('low_risk', [])
    
    score += len(high_risk_perms) * 15
    score += len(medium_risk_perms) * 8
    score += len(low_risk_perms) * 2
    
    # Check for dangerous permission combinations
    dangerous_perms = [p['name'] for p in high_risk_perms]
    
    if ('android.permission.SEND_SMS' in dangerous_perms or 
        'android.permission.READ_SMS' in dangerous_perms) and len(high_risk_perms) >= 3:
        detected_threats.append({
            'type': 'SMS_MALWARE',
            'severity': 'high',
            'description': 'App has SMS permissions combined with other risky permissions - potential SMS fraud',
            'indicators': ['SMS permissions', 'Multiple high-risk permissions']
        })
    
    if ('android.permission.RECORD_AUDIO' in dangerous_perms and 
        'android.permission.ACCESS_FINE_LOCATION' in dangerous_perms):
        detected_threats.append({
            'type': 'SPYWARE',
            'severity': 'high', 
            'description': 'App can record audio and access precise location - potential spyware behavior',
            'indicators': ['Audio recording', 'Location tracking']
        })
    
    if len(high_risk_perms) >= 5:
        detected_threats.append({
            'type': 'EXCESSIVE_PERMISSIONS',
            'severity': 'medium',
            'description': f'App requests {len(high_risk_perms)} high-risk permissions - potential over-privileged app',
            'indicators': [f'{len(high_risk_perms)} high-risk permissions']
        })
    
    # Certificate-based scoring and threat detection
    certificates = analysis_result.get('certificates', [])
    if not certificates:
        score += 20  # No certificate
        detected_threats.append({
            'type': 'UNSIGNED_APK',
            'severity': 'medium',
            'description': 'APK is not properly signed with a certificate',
            'indicators': ['No digital signature']
        })
    else:
        for cert in certificates:
            if not cert.get('is_valid', True):
                score += 15  # Invalid certificate
                detected_threats.append({
                    'type': 'INVALID_CERTIFICATE',
                    'severity': 'high',
                    'description': 'APK has an invalid or expired certificate',
                    'indicators': ['Invalid certificate']
                })
            if 'debug' in cert.get('subject', '').lower():
                score += 10  # Debug certificate
                detected_threats.append({
                    'type': 'DEBUG_CERTIFICATE',
                    'severity': 'medium',
                    'description': 'APK is signed with a debug certificate - not for production use',
                    'indicators': ['Debug certificate']
                })
    
    # Package name-based threat detection
    suspicious_packages = [
        'metasploit', 'exploit', 'payload', 'backdoor', 'trojan', 
        'malware', 'virus', 'rootkit', 'keylog', 'stealer',
        'rat', 'remote', 'hack', 'crack', 'keygen'
    ]
    
    for suspicious in suspicious_packages:
        if suspicious in package_name or suspicious in app_name:
            detected_threats.append({
                'type': 'SUSPICIOUS_PACKAGE_NAME',
                'severity': 'critical',
                'description': f'Package/app name contains suspicious keyword: {suspicious}',
                'indicators': ['Suspicious naming']
            })
            score += 30
            break
    
    # Check for common malware package patterns
    if any(pattern in package_name for pattern in ['com.android.system', 'android.system.core', 'com.google.system']):
        detected_threats.append({
            'type': 'SYSTEM_IMPERSONATION',
            'severity': 'high',
            'description': 'App package name impersonates system applications',
            'indicators': ['System impersonation']
        })
        score += 25
    
    # YARA-based scoring and threat detection
    for threat in yara_threats:
        severity = threat.get('severity', 'medium')
        rule_name = threat.get('rule_name', 'Unknown')
        description = threat.get('description', f'YARA rule {rule_name} triggered')
        
        if severity == 'critical':
            score += 25
        elif severity == 'high':
            score += 20
        elif severity == 'medium':
            score += 10
        else:
            score += 5
        
        # Add YARA detections as threats
        detected_threats.append({
            'type': 'YARA_DETECTION',
            'severity': severity,
            'description': description,
            'indicators': [f'YARA rule: {rule_name}']
        })
    
    # Additional threat detection based on components
    components = analysis_result.get('components', {})
    receivers = components.get('receivers', [])
    services = components.get('services', [])
    
    # Check for suspicious broadcast receivers
    suspicious_receivers = ['BOOT_COMPLETED', 'SMS_RECEIVED', 'PHONE_STATE']
    for receiver in receivers:
        for suspicious in suspicious_receivers:
            if suspicious.lower() in receiver.lower():
                detected_threats.append({
                    'type': 'SUSPICIOUS_RECEIVER',
                    'severity': 'medium',
                    'description': f'App registers suspicious broadcast receiver: {suspicious}',
                    'indicators': ['Suspicious broadcast receiver']
                })
                score += 10
                break
    
    # Cap score at 100
    final_score = min(score, 100)
    
    return final_score, detected_threats

@app.route('/')
def index():
    """Serve the main HTML page"""
    return send_from_directory('.', 'index.html')

@app.route('/css/<path:filename>')
def css_files(filename):
    """Serve CSS files"""
    return send_from_directory('css', filename)

@app.route('/js/<path:filename>')
def js_files(filename):
    """Serve JavaScript files"""
    return send_from_directory('js', filename)

@app.route('/api/upload', methods=['POST'])
def upload_file():
    """Handle file upload and analysis"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'error': 'Invalid file type. Only APK files are allowed.'}), 400
        
        # Secure filename and save
        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        unique_filename = f"{timestamp}_{filename}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        
        file.save(file_path)
        
        # Load YARA rules
        yara_rules = load_yara_rules()
        
        # Perform APK analysis
        analysis_result = analyze_apk(file_path)
        
        # Perform YARA scanning
        yara_threats = scan_with_yara(file_path, yara_rules) if yara_rules else []
        
        # Calculate risk score and detect threats
        risk_score, detected_threats = calculate_risk_score_and_threats(analysis_result, yara_threats)
        
        # Prepare response
        response = {
            'success': True,
            'filename': filename,
            'analysis': analysis_result,
            'yara_threats': yara_threats,
            'detected_threats': detected_threats,
            'risk_score': risk_score,
            'scan_timestamp': datetime.now().isoformat(),
            'yara_enabled': YARA_AVAILABLE,
            'androguard_enabled': ANDROGUARD_AVAILABLE
        }
        
        # Clean up uploaded file after analysis
        try:
            os.remove(file_path)
        except:
            pass
        
        return jsonify(response)
        
    except Exception as e:
        print(f"Upload error: {e}")
        traceback.print_exc()
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500

@app.route('/api/status')
def status():
    """Get system status"""
    return jsonify({
        'status': 'online',
        'androguard_available': ANDROGUARD_AVAILABLE,
        'yara_available': YARA_AVAILABLE,
        'yara_rules_count': len(list(Path(YARA_RULES_FOLDER).glob('*.yar'))) if Path(YARA_RULES_FOLDER).exists() else 0,
        'timestamp': datetime.now().isoformat()
    })

@app.errorhandler(413)
def too_large(e):
    """Handle file too large error"""
    return jsonify({'error': 'File too large. Maximum size is 50MB.'}), 413

if __name__ == '__main__':
    print("🔥 APK Malware Scanner - Starting Backend Server")
    print(f"📊 Androguard Available: {ANDROGUARD_AVAILABLE}")
    print(f"🛡️  YARA Available: {YARA_AVAILABLE}")
    
    if Path(YARA_RULES_FOLDER).exists():
        yara_files = list(Path(YARA_RULES_FOLDER).glob('*.yar'))
        print(f"📋 YARA Rules Found: {len(yara_files)}")
    else:
        print("⚠️  No YARA rules directory found")
    
    print("🚀 Server starting on http://localhost:5000")
    print("📝 Access the scanner at: http://localhost:5000")
    print("🔄 API endpoint available at: http://localhost:5000/api/upload")
    
    try:
        app.run(debug=True, host='127.0.0.1', port=5000, threaded=True)
    except Exception as e:
        print(f"❌ Server failed to start: {e}")
