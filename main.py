from flask import Flask, jsonify, request
from flask_cors import CORS
import os
import pefile
import pandas as pd
from sklearn.model_selection import GridSearchCV
from sklearn.ensemble import RandomForestClassifier
import joblib


app = Flask(__name__)


app.config.from_object(__name__)

CORS(app, resources={r"/*": {"origins": "*"}})

# Définir un dossier de sauvegarde des fichiers
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

model_dir = 'models'
model_random_forest_filename = 'random_forest_model.pkl'
model_random_forest_path = os.path.join(model_dir, model_random_forest_filename)


@app.route('/check', methods=['POST'])
def main():
    if 'file' not in request.files:
        return jsonify('No file part'), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify('No selected file'), 400
    if file:
        features = script_extract(file)
        predict =  predict_with_random_forest(features)
        return jsonify(f"{predict[0]}"), 200
    
    

def script_extract(file):
    try:
        pe = pefile.PE(data=file.read())

        # Extraire les informations demandées
        entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        major_linker_version = pe.OPTIONAL_HEADER.MajorLinkerVersion
        major_image_version = pe.OPTIONAL_HEADER.MajorImageVersion
        major_os_version = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
        dll_characteristics = pe.OPTIONAL_HEADER.DllCharacteristics
        stack_reserve_size = pe.OPTIONAL_HEADER.SizeOfStackReserve
        num_sections = len(pe.sections)
        resource_size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']].Size
        
        return [[entry_point, major_linker_version, major_image_version, major_os_version ,dll_characteristics ,stack_reserve_size ,num_sections, resource_size]]

    except Exception as e:
        print(f"Error processing file {file.filename}: {e}")

def predict_with_random_forest(features):
    if not os.path.exists(model_random_forest_path):
        dataset = pd.read_csv("resources/DatasetmalwareExtrait.csv")
        dataset = dataset.values
        X_train = dataset[0:137443, 0:8]
        y_train = dataset[0:137443, 8]
        model = RandomForestClassifier(random_state=42)
        param_of_grid_search = {
            'n_estimators': [10, 50, 100],
            'max_depth': [12, 5, 10, None],
            'min_samples_split': [2, 5, 10],
            'criterion': ['gini', 'entropy']
        }
        grid_search = GridSearchCV(estimator=model, param_grid=param_of_grid_search, n_jobs=-1,  cv=3)
        grid_search.fit(X_train, y_train)
        best_model = grid_search.best_estimator_
        joblib.dump(best_model, model_random_forest_path)
    else:
        best_model = joblib.load(model_random_forest_path)

    y_predict_with_random_forest_with_hyperparameters = best_model.predict(features)

    return y_predict_with_random_forest_with_hyperparameters
