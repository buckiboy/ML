import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, precision_score, recall_score, f1_score
from sklearn.utils.class_weight import compute_class_weight
from flask import Flask, request, jsonify, render_template, redirect, url_for, send_file
import joblib
import os
import matplotlib
import datetime
import logging

matplotlib.use('Agg')
import matplotlib.pyplot as plt

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Ensure the uploads directory exists
if not os.path.exists('uploads'):
    os.makedirs('uploads')

# Ensure the static directory exists
if not os.path.exists('static'):
    os.makedirs('static')

# Ensure the removed directory exists
if not os.path.exists('removed'):
    os.makedirs('removed')

# Define paths for various files
MODEL_PATH = 'model.joblib'
TRAINED_DATA_PATH = 'trained_data.csv'
INITIAL_DATA_PATH = 'alert.csv'
REMOVED_DATA_PATH = 'removed/removed_data.csv'

# Step 1: Read and preprocess CSV data
def preprocess_data(df):
    logger.info(f"Preprocessing data with columns: {df.columns.tolist()}")
    df.fillna(0, inplace=True)

    if 'src' in df.columns:
        df['src_num'] = df['src'].apply(lambda x: int(''.join([f"{int(i):03}" for i in x.split('.')])) if isinstance(x, str) else x)
    if 'dst' in df.columns:
        df['dst_num'] = df['dst'].apply(lambda x: int(''.join([f"{int(i):03}" for i in x.split('.')])) if isinstance(x, str) else x)

    if 'protocol' in df.columns:
        df = pd.get_dummies(df, columns=['protocol'], prefix='', prefix_sep='')
        for proto in ['TCP', 'UDP', 'ICMP']:
            if proto not in df.columns:
                df[proto] = 0
        df.rename(columns={'TCP': 'protocol_TCP', 'UDP': 'protocol_UDP', 'ICMP': 'protocol_ICMP'}, inplace=True)
    else:
        df['protocol_TCP'] = 0
        df['protocol_UDP'] = 0
        df['protocol_ICMP'] = 0

    logger.info(f"Processed data columns: {df.columns.tolist()}")
    return df

# Step 2: Feature Engineering
def feature_engineering(df):
    required_columns = ['src_num', 'sport', 'dst_num', 'dport', 'protocol_TCP', 'protocol_UDP', 'protocol_ICMP']
    for col in required_columns:
        if col not in df.columns:
            df[col] = 0
    X = df[required_columns]
    y = df['label']
    return X, y

# Step 3: Model Training and Evaluation
def train_evaluate_model(X, y):
    class_weights = compute_class_weight(class_weight='balanced', classes=np.unique(y), y=y)
    class_weights_dict = {i: class_weights[i] for i in range(len(class_weights))}

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    model = RandomForestClassifier(n_estimators=100, random_state=42, class_weight=class_weights_dict)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    logger.info("Classification Report:")
    logger.info(classification_report(y_test, y_pred, zero_division=0))
    logger.info(f"Accuracy: {accuracy_score(y_test, y_pred)}")
    logger.info(f"Precision: {precision_score(y_test, y_pred, zero_division=0)}")
    logger.info(f"Recall: {recall_score(y_test, y_pred, zero_division=0)}")
    logger.info(f"F1 Score: {f1_score(y_test, y_pred, zero_division=0)}")
    
    test_results = {
        'classification_report': classification_report(y_test, y_pred, zero_division=0, output_dict=True),
        'accuracy': accuracy_score(y_test, y_pred),
        'precision': precision_score(y_test, y_pred, zero_division=0),
        'recall': recall_score(y_test, y_pred, zero_division=0),
        'f1_score': f1_score(y_test, y_pred, zero_division=0),
        'details': pd.DataFrame({'y_test': y_test, 'y_pred': y_pred}).to_dict(orient='records')
    }
    return model, test_results

# Step 4: Save the model
def save_model(model, model_path='model.joblib'):
    joblib.dump(model, model_path)

# Initialize Flask app and load initial model
app = Flask(__name__)

if os.path.exists(MODEL_PATH):
    model = joblib.load(MODEL_PATH)
else:
    model = None

# Load existing data or initialize empty dataframe
if os.path.exists(TRAINED_DATA_PATH):
    trained_data_df = pd.read_csv(TRAINED_DATA_PATH)
else:
    if os.path.exists(INITIAL_DATA_PATH):
        trained_data_df = pd.read_csv(INITIAL_DATA_PATH)
    else:
        trained_data_df = pd.DataFrame(columns=['src', 'sport', 'dst', 'dport', 'protocol', 'sig_name', 'label', 'source'])

# Train and evaluate the model to get the test results
if model is None and not os.path.exists(MODEL_PATH):
    df = trained_data_df.copy()
    df = preprocess_data(df)
    X, y = feature_engineering(df)
    model, test_results = train_evaluate_model(X, y)
    save_model(model)
else:
    test_results = {}

@app.route('/')
def index():
    trained_data = trained_data_df.to_dict(orient='records')
    return render_template('index.html', prediction=None, trained_data=trained_data, prediction_results=None)

@app.route('/model_performance')
def model_performance():
    return render_template('model_performance.html', test_results=test_results)

@app.route('/predict_calculation', methods=['GET', 'POST'])
def predict_calculation():
    if request.method == 'POST':
        src = request.form['src']
        sport = int(request.form['sport'])
        dst = request.form['dst']
        dport = int(request.form['dport'])
        protocol = request.form['protocol']
        
        feature_dict = {
            'src_num': [int(''.join([f"{int(i):03}" for i in src.split('.')]))],
            'sport': [sport],
            'dst_num': [int(''.join([f"{int(i):03}" for i in dst.split('.')]))],
            'dport': [dport],
            'protocol_TCP': [1 if protocol == 'TCP' else 0],
            'protocol_UDP': [1 if protocol == 'UDP' else 0],
            'protocol_ICMP': [1 if protocol == 'ICMP' else 0]
        }
        features = pd.DataFrame(feature_dict)
        if model:
            try:
                prediction = model.predict(features)
                sig_name = "Reason not available"  # Default reason
                
                match = trained_data_df[(trained_data_df['src'] == src) & 
                                        (trained_data_df['sport'] == sport) & 
                                        (trained_data_df['dst'] == dst) & 
                                        (trained_data_df['dport'] == dport) & 
                                        (trained_data_df[['protocol_TCP', 'protocol_UDP', 'protocol_ICMP']].idxmax(axis=1).apply(lambda x: x.split('_')[1]) == protocol)]
                if not match.empty:
                    sig_name = match.iloc[0]['sig_name']
                
                return render_template('prediction.html', 
                                       prediction=prediction[0], 
                                       src=src, 
                                       sport=sport, 
                                       dst=dst, 
                                       dport=dport, 
                                       protocol=protocol,
                                       sig_name=sig_name,
                                       features=features.to_dict(orient='records')[0])
            except ValueError as e:
                logger.error(f"Error during prediction: {e}")
                return render_template('prediction.html', error=str(e))
        return render_template('prediction.html', prediction=None)
    return render_template('predict_form.html')

@app.route('/predict_form', methods=['POST'])
def predict_form():
    src = request.form['src']
    sport = int(request.form['sport'])
    dst = request.form['dst']
    dport = int(request.form['dport'])
    protocol = request.form['protocol']
    feature_dict = {
        'src_num': [int(''.join([f"{int(i):03}" for i in src.split('.')]))],
        'sport': [sport],
        'dst_num': [int(''.join([f"{int(i):03}" for i in dst.split('.')]))],
        'dport': [dport],
        'protocol_TCP': [1 if protocol == 'TCP' else 0],
        'protocol_UDP': [1 if protocol == 'UDP' else 0],
        'protocol_ICMP': [1 if protocol == 'ICMP' else 0]
    }
    features = pd.DataFrame(feature_dict)
    if model:
        try:
            prediction = model.predict(features)
            sig_name = "Reason not available"  # Default reason
            
            match = trained_data_df[(trained_data_df['src'] == src) & 
                                    (trained_data_df['sport'] == sport) & 
                                    (trained_data_df['dst'] == dst) & 
                                    (trained_data_df['dport'] == dport) & 
                                    (trained_data_df[['protocol_TCP', 'protocol_UDP', 'protocol_ICMP']].idxmax(axis=1).apply(lambda x: x.split('_')[1]) == protocol)]
            if not match.empty:
                sig_name = match.iloc[0]['sig_name']
        except ValueError as e:
            logger.error(f"Error during prediction: {e}")
            prediction = [0]  # Default to non-threat if there's an error
            sig_name = "Error during prediction"
    else:
        prediction = [0]
        sig_name = "Model not available"

    trained_data = trained_data_df.to_dict(orient='records')
    return render_template('index.html', prediction=prediction[0], src=src, sport=sport, dst=dst, dport=dport, protocol=protocol, sig_name=sig_name, trained_data=trained_data, prediction_results=None)

@app.route('/predict_file', methods=['POST'])
def predict_file():
    if 'file' not in request.files:
        return redirect(url_for('index'))

    file = request.files['file']
    if file.filename == '':
        return redirect(url_for('index'))

    if file and file.filename.endswith('.csv'):
        file_path = os.path.join('uploads', file.filename)
        file.save(file_path)
        df = pd.read_csv(file_path)
        df = preprocess_data(df)
        logger.info(f"Data after preprocessing: {df.head()}")
        
        # Ensure all necessary columns are present
        required_columns = ['src', 'sport', 'dst', 'dport', 'protocol_TCP', 'protocol_UDP', 'protocol_ICMP']
        for col in required_columns:
            if col not in df.columns:
                df[col] = 0
        
        features = df[['src_num', 'sport', 'dst_num', 'dport', 'protocol_TCP', 'protocol_UDP', 'protocol_ICMP']]
        if model:
            predictions = model.predict(features)
            df['prediction'] = predictions
            df['protocol'] = df[['protocol_TCP', 'protocol_UDP', 'protocol_ICMP']].idxmax(axis=1).apply(lambda x: x.split('_')[1])
            prediction_results = df[['src', 'sport', 'dst', 'dport', 'protocol', 'prediction']].to_dict(orient='records')
            for result in prediction_results:
                match = trained_data_df[(trained_data_df['src'] == result['src']) & 
                                        (trained_data_df['sport'] == result['sport']) & 
                                        (trained_data_df['dst'] == result['dst']) & 
                                        (trained_data_df['dport'] == result['dport']) & 
                                        (trained_data_df[['protocol_TCP', 'protocol_UDP', 'protocol_ICMP']].idxmax(axis=1).apply(lambda x: x.split('_')[1]) == result['protocol'])]
                result['sig_name'] = match.iloc[0]['sig_name'] if not match.empty else "Reason not available"
            return render_template('prediction_results.html', prediction_results=prediction_results, file_path=file_path)
    return redirect(url_for('index'))

@app.route('/label_predictions', methods=['POST'])
def label_predictions():
    global trained_data_df
    data = request.form.to_dict(flat=False)
    new_entries = []

    for i in range(len(data['src'])):
        new_entry = {
            'src': data['src'][i],
            'sport': data['sport'][i],
            'dst': data['dst'][i],
            'dport': data['dport'][i],
            'protocol': data['protocol'][i],
            'sig_name': data['sig_name'][i],
            'label': int(data['label'][i]),
            'source': 'file'
        }
        new_entries.append(new_entry)

    new_entries_df = pd.DataFrame(new_entries)
    trained_data_df = pd.concat([trained_data_df, new_entries_df], ignore_index=True)
    trained_data_df.to_csv(TRAINED_DATA_PATH, index=False)

    return redirect(url_for('index'))

@app.route('/label', methods=['POST'])
def label():
    global trained_data_df
    src = request.form['src']
    sport = request.form['sport']
    dst = request.form['dst']
    dport = request.form['dport']
    protocol = request.form['protocol']
    sig_name = request.form['sig_name']
    label = int(request.form['label'])

    manual_label = {
        'src': src,
        'sport': sport,
        'dst': dst,
        'dport': dport,
        'protocol': protocol,
        'sig_name': sig_name,
        'label': label,
        'source': 'manual'
    }

    # Convert the manual label to DataFrame and concatenate with existing trained data
    manual_label_df = pd.DataFrame([manual_label])
    trained_data_df = pd.concat([trained_data_df, manual_label_df], ignore_index=True)
    trained_data_df.to_csv(TRAINED_DATA_PATH, index=False)

    return redirect(url_for('index'))

@app.route('/delete/<int:index>', methods=['POST'])
def delete(index):
    global trained_data_df
    trained_data_df = trained_data_df.drop(index).reset_index(drop=True)
    trained_data_df.to_csv(TRAINED_DATA_PATH, index=False)
    return redirect(url_for('index'))

@app.route('/add_prediction', methods=['POST'])
def add_prediction():
    global trained_data_df
    src = request.form['src']
    sport = request.form['sport']
    dst = request.form['dst']
    dport = request.form['dport']
    protocol = request.form['protocol']
    sig_name = request.form['sig_name']
    label = int(request.form['label'])

    new_data = {
        'src': src,
        'sport': sport,
        'dst': dst,
        'dport': dport,
        'protocol': protocol,
        'sig_name': sig_name,
        'label': label,
        'source': 'manual'
    }

    new_data_df = pd.DataFrame([new_data])
    trained_data_df = pd.concat([trained_data_df, new_data_df], ignore_index=True)
    trained_data_df.to_csv(TRAINED_DATA_PATH, index=False)

    return redirect(url_for('index'))

@app.route('/retrain', methods=['POST'])
def retrain():
    global model, test_results, trained_data_df
    df = trained_data_df.copy()
    df = preprocess_data(df)
    
    # Remove duplicates
    duplicates = df[df.duplicated()]
    if not duplicates.empty:
        timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        duplicates.loc[:, 'timestamp'] = timestamp
        if os.path.exists(REMOVED_DATA_PATH):
            duplicates.to_csv(REMOVED_DATA_PATH, mode='a', header=False, index=False)
        else:
            duplicates.to_csv(REMOVED_DATA_PATH, mode='w', header=True, index=False)
        df = df.drop_duplicates()

    X, y = feature_engineering(df)

    # Retrain model with combined data
    model, test_results = train_evaluate_model(X, y)
    save_model(model)
    
    # Update the trained data file
    df.to_csv(TRAINED_DATA_PATH, index=False)
    trained_data_df = df

    return redirect(url_for('index'))

@app.route('/removed_data')
def removed_data():
    if os.path.exists(REMOVED_DATA_PATH):
        removed_data_df = pd.read_csv(REMOVED_DATA_PATH)
        removed_data = removed_data_df.to_dict(orient='records')
    else:
        removed_data = []
    return render_template('removed_data.html', removed_data=removed_data)

@app.route('/trained_data_graph')
def trained_data_graph():
    threat_count = trained_data_df['label'].value_counts().sort_index()
    labels = ['No Threat', 'Threat']
    colors = ['blue', 'red']
    plt.figure(figsize=(6, 4))
    plt.pie(threat_count, labels=labels, colors=colors, autopct='%1.1f%%', startangle=140)
    plt.title('Trained Data Breakdown by Threat and No Threat')
    plt.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
    plt.tight_layout()
    plt.savefig('static/trained_data_graph.png')
    return send_file('static/trained_data_graph.png', mimetype='image/png')

if __name__ == '__main__':
    if not model:
        # Load initial data and train model if it doesn't exist
        if os.path.exists(INITIAL_DATA_PATH):
            df = pd.read_csv(INITIAL_DATA_PATH)
            df['source'] = 'file'
            df = preprocess_data(df)
            X, y = feature_engineering(df)
            model, test_results = train_evaluate_model(X, y)
            save_model(model)

    # Always ensure to use the complete trained dataset (initial + manually added)
    if os.path.exists(TRAINED_DATA_PATH):
        trained_data_df = pd.read_csv(TRAINED_DATA_PATH)

    app.run(debug=True)
