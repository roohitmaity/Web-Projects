# app.py
from flask import Flask, render_template, jsonify, request, send_file, redirect, url_for, session
import pandas as pd
import numpy as np
import json
import os
import subprocess
import threading
import time
import plotly
import plotly.express as px
import plotly.utils
import yaml
import joblib
import secrets
from datetime import datetime

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['DATA_DIR'] = 'data'
app.config['MODELS_DIR'] = 'models'
app.config['RULES_DIR'] = 'rules'
app.config['LOGS_DIR'] = 'logs'

# Global variables
evolution_thread = None
evolution_running = False

# Ensure directories exist
os.makedirs(app.config['DATA_DIR'], exist_ok=True)
os.makedirs(app.config['MODELS_DIR'], exist_ok=True)
os.makedirs(app.config['RULES_DIR'], exist_ok=True)
os.makedirs(app.config['LOGS_DIR'], exist_ok=True)


@app.template_filter('filesize')
def filesize_filter(size):
    """Convert bytes to human readable format"""
    if not size:
        return "0 B"

    try:
        size = float(size)
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} PB"
    except (ValueError, TypeError):
        return str(size)


@app.context_processor
def utility_processor():
    return {'now': datetime.now}


def get_python_executable():
    """Get the current Python executable path"""
    import sys
    return sys.executable


def load_detection_results():
    """Load detection results if available"""
    try:
        df = pd.read_csv(os.path.join(app.config['DATA_DIR'], 'detection_results.csv'))
        return df
    except:
        return None


def load_rules():
    """Load all generated rules"""
    rules = []
    if os.path.exists(app.config['RULES_DIR']):
        for file in os.listdir(app.config['RULES_DIR']):
            if file.endswith('.yml'):
                try:
                    with open(os.path.join(app.config['RULES_DIR'], file), 'r') as f:
                        rule = yaml.safe_load(f)
                        rules.append({
                            'file': file,
                            'title': rule.get('title', 'Unknown'),
                            'severity': rule.get('level', 'medium'),
                            'description': rule.get('description', ''),
                            'content': yaml.dump(rule, default_flow_style=False)
                        })
                except:
                    pass
    return rules


def load_evolution_history():
    """Load evolution history"""
    try:
        with open(os.path.join(app.config['LOGS_DIR'], 'evolution_log.json'), 'r') as f:
            return json.load(f)
    except:
        return {'iterations': [], 'performance_metrics': [], 'rules_generated': []}


def get_system_stats():
    """Get system statistics"""
    df = load_detection_results()
    rules = load_rules()
    evolution = load_evolution_history()

    stats = {
        'total_events': 0,
        'anomalies': 0,
        'anomaly_rate': 0,
        'active_rules': len(rules),
        'evolution_cycles': len(evolution.get('iterations', [])),
        'models_trained': len([f for f in os.listdir('models') if f.endswith('.pkl')]) if os.path.exists(
            'models') else 0,
        'last_update': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }

    if df is not None:
        stats['total_events'] = len(df)
        anomaly_col = 'ae_anomaly' if 'ae_anomaly' in df.columns else 'iso_anomaly'
        if anomaly_col in df.columns:
            stats['anomalies'] = int(df[anomaly_col].sum())
            stats['anomaly_rate'] = round(stats['anomalies'] / len(df) * 100, 2)

    return stats


def get_performance_metrics():
    """Get latest performance metrics"""
    df = load_detection_results()
    if df is None:
        return None

    metrics = {}

    # Find columns
    anomaly_col = 'ae_anomaly' if 'ae_anomaly' in df.columns else 'iso_anomaly'
    attack_col = None
    for col in ['Is Attack IP', 'Is Account Takeover', 'true_attack']:
        if col in df.columns:
            attack_col = col
            break

    if attack_col and anomaly_col in df.columns:
        true_pos = ((df[anomaly_col] == True) & (df[attack_col] == True)).sum()
        false_pos = ((df[anomaly_col] == True) & (df[attack_col] == False)).sum()
        false_neg = ((df[anomaly_col] == False) & (df[attack_col] == True)).sum()
        true_neg = ((df[anomaly_col] == False) & (df[attack_col] == False)).sum()

        total_attacks = true_pos + false_neg
        total_normal = false_pos + true_neg

        metrics['detection_rate'] = round((true_pos / total_attacks * 100), 2) if total_attacks > 0 else 0
        metrics['false_positive_rate'] = round((false_pos / total_normal * 100), 2) if total_normal > 0 else 0

        precision = true_pos / (true_pos + false_pos) if (true_pos + false_pos) > 0 else 0
        recall = true_pos / (true_pos + false_neg) if (true_pos + false_neg) > 0 else 0
        metrics['f1_score'] = round(2 * (precision * recall) / (precision + recall), 3) if (
                                                                                                   precision + recall) > 0 else 0

        metrics['true_positives'] = int(true_pos)
        metrics['false_positives'] = int(false_pos)
        metrics['false_negatives'] = int(false_neg)
        metrics['true_negatives'] = int(true_neg)

    return metrics


def create_anomaly_chart():
    """Create plotly chart of anomalies over time"""
    df = load_detection_results()
    if df is None or 'login_hour' not in df.columns:
        return None

    anomaly_col = 'ae_anomaly' if 'ae_anomaly' in df.columns else 'iso_anomaly'

    hourly = df.groupby('login_hour')[anomaly_col].agg(['sum', 'count']).reset_index()
    hourly['rate'] = (hourly['sum'] / hourly['count'] * 100)

    fig = px.bar(hourly, x='login_hour', y='sum',
                 title='Anomalies by Hour of Day',
                 labels={'login_hour': 'Hour', 'sum': 'Anomaly Count'},
                 color='rate',
                 color_continuous_scale='Reds')

    return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)


def create_country_chart():
    """Create chart of top anomalous countries"""
    df = load_detection_results()
    if df is None:
        return None

    anomaly_col = 'ae_anomaly' if 'ae_anomaly' in df.columns else 'iso_anomaly'

    if 'Country' in df.columns:
        country_stats = df[df[anomaly_col]]['Country'].value_counts().head(10)

        fig = px.bar(x=country_stats.values, y=country_stats.index,
                     title='Top 10 Countries with Anomalies',
                     labels={'x': 'Anomaly Count', 'y': 'Country'},
                     orientation='h',
                     color=country_stats.values,
                     color_continuous_scale='Reds')

        return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)
    return None


def create_trend_chart():
    """Create evolution trend chart"""
    evolution = load_evolution_history()
    metrics = evolution.get('performance_metrics', [])

    if len(metrics) < 2:
        return None

    df = pd.DataFrame(metrics)
    df['cycle'] = range(1, len(df) + 1)

    fig = px.line(df, x='cycle', y=['detection_rate', 'f1_score'],
                  title='Performance Over Evolution Cycles',
                  labels={'value': 'Score', 'cycle': 'Evolution Cycle', 'variable': 'Metric'},
                  markers=True)

    return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)


@app.route('/')
def index():
    """Dashboard homepage"""
    stats = get_system_stats()
    anomaly_chart = create_anomaly_chart()
    country_chart = create_country_chart()
    trend_chart = create_trend_chart()
    metrics = get_performance_metrics()

    return render_template('index.html',
                           stats=stats,
                           metrics=metrics,
                           anomaly_chart=anomaly_chart,
                           country_chart=country_chart,
                           trend_chart=trend_chart)

@app.route('/dashboard')
def dashboard_redirect():
    return redirect(url_for('index'))

@app.route('/import')
def import_page():
    """Landing page - dataset import"""
    try:
        # Get list of recent datasets with their sizes
        recent = []
        if os.path.exists(app.config['DATA_DIR']):
            for f in os.listdir(app.config['DATA_DIR']):
                if f.endswith('.csv') and not f.startswith('temp_') and f != 'active_dataset.csv':
                    file_path = os.path.join(app.config['DATA_DIR'], f)
                    file_size = os.path.getsize(file_path)
                    file_time = os.path.getmtime(file_path)
                    recent.append({
                        'name': f,
                        'size': file_size,  # Pass the actual file size in bytes
                        'modified': datetime.fromtimestamp(file_time).strftime('%Y-%m-%d %H:%M')
                    })

            # Sort by modification time, newest first
            recent.sort(key=lambda x: x['modified'], reverse=True)

        return render_template('import.html', recent_datasets=recent[:10])  # Show last 10
    except Exception as e:
        print(f"Error in import_page: {e}")
        return render_template('import.html', recent_datasets=[])


@app.route('/api/dataset-info', methods=['POST'])
def dataset_info():
    """Get info about a dataset without loading it fully"""
    try:
        data = request.get_json()
        filename = data.get('filename')

        filepath = os.path.join(app.config['DATA_DIR'], filename)
        if not os.path.exists(filepath):
            return jsonify({'success': False, 'message': 'File not found'})

        # Get total rows (fast method - just count lines)
        with open(filepath, 'r', encoding='utf-8') as f:
            total_rows = sum(1 for _ in f) - 1  # Subtract header

        # Read first 10 rows for preview
        df = pd.read_csv(filepath, nrows=10)

        return jsonify({
            'success': True,
            'filename': filename,
            'path': filepath,
            'total_rows': total_rows,
            'columns': df.columns.tolist(),
            'preview': df.to_dict('records')
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})


@app.route('/api/upload-preview', methods=['POST'])
def upload_preview():
    """Upload and preview a new file"""
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'message': 'No file uploaded'})

        file = request.files['file']
        filename = file.filename

        # Save temporarily
        temp_path = os.path.join(app.config['DATA_DIR'], 'temp_' + filename)
        file.save(temp_path)

        # Get total rows
        with open(temp_path, 'r', encoding='utf-8') as f:
            total_rows = sum(1 for _ in f) - 1

        # Read first 10 rows for preview
        df = pd.read_csv(temp_path, nrows=10)

        return jsonify({
            'success': True,
            'filename': filename,
            'path': temp_path,
            'total_rows': total_rows,
            'columns': df.columns.tolist(),
            'preview': df.to_dict('records')
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})


@app.route('/api/import-dataset', methods=['POST'])
def import_dataset():
    """Import dataset with specified number of rows"""
    try:
        data = request.get_json()
        filepath = data.get('filepath')
        rows_to_import = data.get('rows', 100000)
        column_map = data.get('columns', {})

        if not os.path.exists(filepath):
            return jsonify({'success': False, 'message': 'File not found'})

        # Read specified number of rows
        df = pd.read_csv(filepath, nrows=rows_to_import)

        # Apply column mapping
        rename_map = {}
        if column_map.get('timestamp'):
            rename_map[column_map['timestamp']] = 'Login Timestamp'
        if column_map.get('user'):
            rename_map[column_map['user']] = 'User ID'
        if column_map.get('ip'):
            rename_map[column_map['ip']] = 'IP Address'
        if column_map.get('country'):
            rename_map[column_map['country']] = 'Country'
        if column_map.get('device'):
            rename_map[column_map['device']] = 'Device Type'
        if column_map.get('success'):
            rename_map[column_map['success']] = 'Login Successful'
        if column_map.get('attack'):
            rename_map[column_map['attack']] = 'Is Attack IP'

        if rename_map:
            df = df.rename(columns=rename_map)

        # Save as active dataset
        active_path = os.path.join(app.config['DATA_DIR'], 'active_dataset.csv')
        df.to_csv(active_path, index=False)

        # Also save as detection_results.csv for compatibility
        detection_path = os.path.join(app.config['DATA_DIR'], 'detection_results.csv')
        df.to_csv(detection_path, index=False)

        # Clean up temp file if it exists
        if 'temp_' in filepath:
            os.remove(filepath)

        # Get file size
        size_mb = round(os.path.getsize(active_path) / (1024 * 1024), 2)

        return jsonify({
            'success': True,
            'rows': len(df),
            'columns': len(df.columns),
            'size_mb': size_mb
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})


@app.route('/api/recent-datasets')
def recent_datasets():
    """Get list of recent datasets"""
    try:
        files = []
        if os.path.exists(app.config['DATA_DIR']):
            for f in os.listdir(app.config['DATA_DIR']):
                if f.endswith('.csv') and not f.startswith('temp_') and f != 'active_dataset.csv':
                    path = os.path.join(app.config['DATA_DIR'], f)
                    size = os.path.getsize(path) / (1024 * 1024)  # MB
                    modified = datetime.fromtimestamp(os.path.getmtime(path))
                    files.append({
                        'name': f,
                        'size': round(size, 2),
                        'modified': modified.strftime('%Y-%m-%d %H:%M')
                    })

        # Sort by modified date, newest first
        files.sort(key=lambda x: x['modified'], reverse=True)
        return jsonify(files)
    except Exception as e:
        return jsonify([])


@app.route('/api/dataset-stats')
def dataset_stats():
    """Get statistics about current dataset"""
    try:
        df = pd.read_csv(os.path.join(app.config['DATA_DIR'], 'active_dataset.csv'))

        stats = {
            'rows': len(df),
            'columns': len(df.columns),
            'attacks': 0
        }

        # Count attacks if column exists
        for col in ['Is Attack IP', 'Is Account Takeover', 'true_attack']:
            if col in df.columns:
                stats['attacks'] = int(df[col].sum())
                break

        return jsonify(stats)
    except:
        return jsonify({'rows': 0, 'columns': 0, 'attacks': 0})


@app.route('/api/check-data')
def check_data():
    """Check if we have existing data"""
    has_data = os.path.exists(os.path.join(app.config['DATA_DIR'], 'detection_results.csv'))
    return jsonify({'has_data': has_data})


@app.route('/anomalies')
def anomalies():
    """Anomalies viewer page"""
    df = load_detection_results()

    if df is None:
        return render_template('anomalies.html', anomalies=[], total=0, columns=[], countries=[], devices=[])

    # Determine anomaly column
    anomaly_col = 'ae_anomaly' if 'ae_anomaly' in df.columns else 'iso_anomaly'

    # Get anomalies only
    if anomaly_col in df.columns:
        anomalies_df = df[df[anomaly_col] == True].copy()

        # Select columns to display
        display_cols = []
        for col in ['Login Timestamp', 'User ID', 'IP Address', 'Country', 'Device Type',
                    'Login Successful', 'ae_score']:
            if col in anomalies_df.columns:
                display_cols.append(col)

        if display_cols:
            anomalies_df = anomalies_df[display_cols]

            # Get unique values for filters
            countries = []
            devices = []

            if 'Country' in anomalies_df.columns:
                countries = anomalies_df['Country'].dropna().unique().tolist()
                countries.sort()

            if 'Device Type' in anomalies_df.columns:
                devices = anomalies_df['Device Type'].dropna().unique().tolist()
                devices.sort()

            # Convert to dict for template (limit to first 1000 for performance)
            anomalies_data = anomalies_df.head(1000).to_dict('records')
            total_anomalies = len(anomalies_df)
        else:
            anomalies_data = []
            total_anomalies = 0
            countries = []
            devices = []
    else:
        anomalies_data = []
        total_anomalies = 0
        countries = []
        devices = []

    return render_template('anomalies.html',
                           anomalies=anomalies_data,
                           total=total_anomalies,
                           columns=display_cols if 'display_cols' in locals() else [],
                           countries=countries,
                           devices=devices)


@app.route('/rules')
def rules():
    """Rules management page"""
    rules_list = load_rules()

    # Group by severity
    rules_by_severity = {
        'critical': [r for r in rules_list if r['severity'] == 'critical'],
        'high': [r for r in rules_list if r['severity'] == 'high'],
        'medium': [r for r in rules_list if r['severity'] == 'medium'],
        'low': [r for r in rules_list if r['severity'] == 'low']
    }

    return render_template('rules.html',
                           rules=rules_list,
                           rules_by_severity=rules_by_severity,
                           total_rules=len(rules_list))


@app.route('/evolution')
def evolution():
    """Evolution tracking page"""
    evolution_data = load_evolution_history()
    metrics = evolution_data.get('performance_metrics', [])

    # Create performance chart
    perf_chart = None
    if len(metrics) >= 2:
        df = pd.DataFrame(metrics)
        df['cycle'] = range(1, len(df) + 1)
        fig = px.line(df, x='cycle', y=['detection_rate', 'f1_score', 'false_positive_rate'],
                      title='Performance Metrics Over Time',
                      markers=True)
        perf_chart = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    return render_template('evolution.html',
                           evolution=evolution_data,
                           metrics=metrics,
                           perf_chart=perf_chart,
                           cycles=len(evolution_data.get('iterations', [])),
                           total_rules=sum(r.get('count', 0) for r in evolution_data.get('rules_generated', [])))



@app.route('/api/run/anomaly', methods=['POST'])
def run_anomaly_detector():
    """Run anomaly detector"""
    try:
        python_exe = get_python_executable()
        result = subprocess.run([python_exe, 'anomaly_detector.py'],
                                capture_output=True, text=True, timeout=3600)

        if result.returncode == 0:
            return jsonify({'success': True, 'message': 'Anomaly detection completed successfully'})
        else:
            return jsonify({'success': False, 'message': f'Error: {result.stderr[:200]}'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})


@app.route('/api/run/rules', methods=['POST'])
def run_rule_generator():
    """Run rule generator"""
    try:
        python_exe = get_python_executable()
        result = subprocess.run([python_exe, 'rule_generator.py'],
                                capture_output=True, text=True, timeout=1800)

        if result.returncode == 0:
            return jsonify({'success': True, 'message': 'Rule generation completed successfully'})
        else:
            return jsonify({'success': False, 'message': f'Error: {result.stderr[:200]}'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})


@app.route('/api/run/evolve', methods=['POST'])
def run_evolution():
    """Run evolution cycle"""
    global evolution_thread, evolution_running

    if evolution_running:
        return jsonify({'success': False, 'message': 'Evolution already running'})

    def run_cycle():
        global evolution_running
        evolution_running = True
        try:
            python_exe = get_python_executable()
            subprocess.run([python_exe, 'self_evolve.py'],
                           capture_output=True, text=True, timeout=7200)
        finally:
            evolution_running = False

    evolution_thread = threading.Thread(target=run_cycle)
    evolution_thread.start()

    return jsonify({'success': True, 'message': 'Evolution cycle started in background'})


@app.route('/api/status/evolution')
def evolution_status():
    """Check if evolution is running"""
    return jsonify({'running': evolution_running})


@app.route('/api/rule/<filename>')
def get_rule_content(filename):
    """Get rule content for viewing"""
    try:
        rule_path = os.path.join(app.config['RULES_DIR'], filename)
        if os.path.exists(rule_path):
            with open(rule_path, 'r') as f:
                content = f.read()
            return jsonify({'success': True, 'content': content})
        else:
            return jsonify({'success': False, 'message': 'Rule not found'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})


@app.route('/api/download/rule/<filename>')
def download_rule(filename):
    """Download a rule file"""
    try:
        return send_file(os.path.join(app.config['RULES_DIR'], filename),
                         as_attachment=True,
                         download_name=filename)
    except:
        return jsonify({'success': False, 'message': 'File not found'})


@app.route('/api/stats/refresh')
def refresh_stats():
    """Get fresh statistics"""
    stats = get_system_stats()
    metrics = get_performance_metrics()
    return jsonify({'stats': stats, 'metrics': metrics})


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)