import csv
import os
import pprint
import random as rn

import tensorflow as tf

from util_functions import *

# Seed Random Numbers
os.environ['PYTHONHASHSEED'] = str(SEED)
np.random.seed(SEED)
rn.seed(SEED)
config = tf.compat.v1.ConfigProto(inter_op_parallelism_threads=1)

from tensorflow.keras.optimizers import Adam
from tensorflow.keras.layers import Dense, Activation, Flatten, Conv2D
from tensorflow.keras.layers import Dropout, GlobalMaxPooling2D
from tensorflow.keras.models import Sequential, load_model
from sklearn.metrics import f1_score, accuracy_score, confusion_matrix
from sklearn.utils import shuffle
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint
# from tensorflow.keras.wrappers.scikit_learn import KerasClassifier
from scikeras.wrappers import KerasClassifier
from sklearn.model_selection import GridSearchCV
from dataset_parser_v2 import *

import tensorflow.keras.backend as K



tf.random.set_seed(SEED)
K.set_image_data_format('channels_last')
tf.compat.v1.logging.set_verbosity(tf.compat.v1.logging.ERROR)
config.gpu_options.allow_growth = True  # dynamically grow the memory used on the GPU
# config.log_device_placement = True  # to log device placement (on which device the operation ran)

OUTPUT_FOLDER = "./output/"

VAL_HEADER = ['Model', 'Samples', 'Accuracy', 'F1Score', 'Hyper-parameters', 'Validation Set']
PREDICT_HEADER = ['Model', 'Time', 'Packets', 'Samples', 'DDOS%', 'Accuracy', 'F1Score', 'TPR', 'FPR', 'TNR', 'FNR',
                  'Source']

# hyperparameters
PATIENCE = 10
DEFAULT_EPOCHS = 1000
hyperparamters = {
    "learning_rate": [0.1, 0.01, 0.001],
    "batch_size": [1024, 2048],
    "kernels": [1, 2, 4, 8, 16, 32, 64],
    "regularization": ['l1', 'l2'],
    "dropout": [0.5, 0.7, 0.9]
}


def Conv2DModel(model_name, input_shape, kernel_col, kernels=64, kernel_rows=3, learning_rate=0.01, regularization=None,
                dropout=None):
    """
    Creates a Convolutional Neural Network (CNN) model using TensorFlow/Keras.

    Args:
        model_name (str): Name of the model.
        input_shape (tuple): Shape of the input data (excluding batch size). For example, (height, width, channels).
        kernel_col (int): Number of columns in the convolutional kernels.
        kernels (int, optional): Number of kernels/filters in the convolutional layer. Defaults to 64.
        kernel_rows (int, optional): Number of rows in the convolutional kernels. Defaults to 3.
        learning_rate (float, optional): Learning rate for the optimizer. Defaults to 0.01.
        regularization (str or None, optional): Regularization method ('l1' or 'l2') or None for no regularization.
        dropout (float or None, optional): Dropout rate between 0 and 1, or None for no dropout.

    Returns:
        keras.models.Sequential: Compiled CNN model.
    """
    # TODO: Implement the Conv2DModel function to create a CNN model and compile it using the compileModel function.
    # Steps:
    # 1. Clear the Keras session to start with a clean state.

    K.clear_session()

    # 2. Create a Sequential model with the given model_name.

    model = Sequential(name=model_name)

    # 3. Add a Conv2D layer with specified parameters, including kernel_regularizer if regularization is provided.

    model.add(Conv2D(kernels, (kernel_rows, kernel_col), input_shape=input_shape, kernel_regularizer=regularization, strides=(1, 1)))

    # 4. Optionally add a Dropout layer based on the provided dropout rate.

    if dropout:
        model.add(Dropout(dropout))

    model.add(Activation('relu'))

    # 5. Add an Activation layer with 'relu' activation function.
    # 6. Add GlobalMaxPooling2D layer, Flatten layer, and a Dense layer with 'sigmoid' activation for binary
    # classification.

    model.add(GlobalMaxPooling2D())
    model.add(Flatten())
    model.add(Dense(1, activation='sigmoid'))

    # 7. Print the model summary.

    # print(model.summary())

    # 8. Compile the model using the compileModel function with the specified learning_rate.

    compileModel(model, learning_rate)

    # 9. Return the compiled model.
    return model


def compileModel(model, lr):
    """
    Compiles a Keras model with specified optimizer and loss function.

    Args:
        model (keras.models.Model): Keras model to compile.
        lr (float): Learning rate for the optimizer.

    Returns:
        None
    """
    # TODO: Implement the compileModel function to compile the given Keras model.
    # Steps:
    # 1. Choose an optimizer (e.g., Adam) with the given learning rate.

    optimizer = Adam(learning_rate=lr, epsilon=None, decay=0.0, amsgrad=False)

    model.compile(optimizer=optimizer, loss='binary_crossentropy', metrics=['accuracy'])


    # 2. Compile the model using 'binary_crossentropy' loss for binary classification and the chosen optimizer.
    # 3. Specify metrics to monitor during training, such as accuracy.


def main():
    help_string = 'Usage: python3 cnn.py --train <dataset_folder> -e <epocs>'

    parser = argparse.ArgumentParser(
        description='DDoS attacks detection with convolutional neural networks',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument('-t', '--train', nargs='+', type=str,
                        help='Start the training process')

    parser.add_argument('-e', '--epochs', default=DEFAULT_EPOCHS, type=int,
                        help='Training iterations')

    parser.add_argument('-cv', '--cross_validation', default=0, type=int,
                        help='Number of folds for cross-validation (default 0)')

    parser.add_argument('-a', '--attack_net', default=None, type=str,
                        help='Subnet of the attacker (used to compute the detection accuracy)')

    parser.add_argument('-v', '--victim_net', default=None, type=str,
                        help='Subnet of the victim (used to compute the detection accuracy)')

    parser.add_argument('-p', '--predict', nargs='?', type=str,
                        help='Perform a prediction on pre-preprocessed data')

    parser.add_argument('-pl', '--predict_live', nargs='?', type=str,
                        help='Perform a prediction on live traffic')

    parser.add_argument('-i', '--iterations', default=1, type=int,
                        help='Predict iterations')

    parser.add_argument('-m', '--model', type=str,
                        help='File containing the model')

    parser.add_argument('-y', '--dataset_type', default=None, type=str,
                        help='Type of the dataset. Available options are: DOS2017, DOS2018, DOS2019, SYN2020')

    args = parser.parse_args()

    """
    Main function to perform training and/or prediction tasks based on command-line arguments.

    Returns:
        None
    """
    # TODO: Implement the main function to handle training and prediction tasks based on command-line arguments.
    # Steps:
    # 1. Check if the output folder exists, if not, create it.
    # 2. If training is specified, perform training on the provided dataset folders.
    #    a. Iterate through each dataset folder.
    #    b. Load training and validation datasets.
    #    c. Shuffle the data.
    #    d. Extract information from filenames (time_window, max_flow_len, dataset_name).
    #    e. Create a KerasClassifier using Conv2DModel and perform hyperparameter optimization with GridSearchCV.
    #    f. Save the best model based on validation performance.
    #    g. Evaluate the best model on the validation set and save performance metrics.
    # 3. If prediction is specified, perform prediction tasks on the specified dataset or live traffic.
    #    a. Load the trained model(s).
    #    b. Predict on the dataset or live traffic and evaluate performance metrics.
    #    c. Save prediction results to a CSV file.

    if os.path.isdir(OUTPUT_FOLDER) == False:
        os.mkdir(OUTPUT_FOLDER)


    if args.train is not None:
        subfolders = glob.glob(args.train[0] + "/*/")
        if len(subfolders) == 0:  # for the case in which the is only one folder, and this folder is args.dataset_folder[0]
            subfolders = [args.train[0] + "/"]
        else:
            subfolders = sorted(subfolders)
        for full_path in subfolders:

            dataset_folder = full_path
            X_train, Y_train = load_dataset(dataset_folder + "/*" + '-train.hdf5')
            X_val, Y_val = load_dataset(dataset_folder + "/*" + '-val.hdf5')

            X_train, Y_train = shuffle(X_train, Y_train, random_state=SEED)
            X_val, Y_val = shuffle(X_val, Y_val, random_state=SEED)

            # get the time_window and the flow_len from the filename
            train_file = glob.glob(dataset_folder + "/*" + '-train.hdf5')[0]
            filename = train_file.split('/')[-1].strip()
            filename = filename.split('\\')[-1].strip()
            time_window = int(filename.split('-')[0].strip().replace('t', ''))
            max_flow_len = int(filename.split('-')[1].strip().replace('n', ''))
            dataset_name = filename.split('-')[2].strip()

            print("\nCurrent dataset folder: ", dataset_folder)

            model_name = dataset_name + "-CNN2024"

            # We're using a grid search combined with K-fold cross-validation to optimize the model's hyperparameters.

            model = KerasClassifier(model=Conv2DModel, input_shape=X_train.shape[1:], kernel_col=X_train.shape[2], model_name=model_name, dropout=None, kernels=64, kernel_rows=3, learning_rate=0.01, regularization=None)

            grid = GridSearchCV(estimator=model, param_grid=hyperparamters, cv=args.cross_validation if args.cross_validation > 1 else [(slice(None), slice(None))], refit=True, return_train_score=True)

            # This approach allows us to explore different configurations and select the one that yields the best
            # performance.

            es = EarlyStopping(monitor='val_loss', mode='min', verbose=1, patience=PATIENCE)

            mc = ModelCheckpoint(OUTPUT_FOLDER + model_name + '.keras', monitor='val_accuracy', mode='max', verbose=1, save_best_only=True)

            grid.fit(X_train, Y_train, validation_data=(X_val, Y_val), callbacks=[es, mc], epochs=args.epochs)

            best_model = grid.best_estimator_.model

            best_model.save(OUTPUT_FOLDER + model_name + '.keras')

            Y_pred_val = (best_model.predict(X_val) > 0.5)
            Y_true_val = Y_val.reshape((Y_val.shape[0], 1))
            f1_score_val = f1_score(Y_true_val, Y_pred_val)
            accuracy = accuracy_score(Y_true_val, Y_pred_val)

            # save best model performance on the validation set
            val_file = open(OUTPUT_FOLDER + model_name + '.csv', 'w', newline='')
            val_file.truncate(0)  # clean the file content (as we open the file in append mode)
            val_writer = csv.DictWriter(val_file, fieldnames=VAL_HEADER)
            val_writer.writeheader()
            val_file.flush()
            row = {'Model': model_name, 'Samples': Y_pred_val.shape[0], 'Accuracy': '{:05.4f}'.format(accuracy),
                   'F1Score': '{:05.4f}'.format(f1_score_val),
                   'Hyper-parameters': grid.best_params_,
                   "Validation Set": glob.glob(dataset_folder + "/*" + '-val.hdf5')[0]}
            val_writer.writerow(row)
            val_file.close()

            print("Best parameters: ", grid.best_params_)
            print("Best model path: ", OUTPUT_FOLDER + model_name + '.keras')
            print("F1 Score of the best model on the validation set: ", f1_score_val)

    if args.predict is not None:
        predict_file = open(OUTPUT_FOLDER + 'predictions-' + time.strftime("%Y%m%d-%H%M%S") + '.csv', 'a',
                            newline='')
        predict_file.truncate(0)  # clean the file content (as we open the file in append mode)
        predict_writer = csv.DictWriter(predict_file, fieldnames=PREDICT_HEADER)
        predict_writer.writeheader()
        predict_file.flush()

        iterations = args.iterations

        dataset_filelist = glob.glob(args.predict + "/*test.hdf5")

        if args.model is not None:
            model_list = [args.model]
        else:
            model_list = glob.glob(args.predict + "/*.h5")

        for model_path in model_list:
            model_filename = model_path.split('/')[-1].strip()
            filename_prefix = model_filename.split('-')[0].strip() + '-' + model_filename.split('-')[
                1].strip() + '-'
            model_name_string = model_filename.split(filename_prefix)[1].strip().split('.')[0].strip()
            model = load_model(model_path)

            # warming up the model (necessary for the GPU)
            warm_up_file = dataset_filelist[0]
            filename = warm_up_file.split('/')[-1].strip()
            if filename_prefix in filename:
                X, Y = load_dataset(warm_up_file)
                Y_pred = np.squeeze(model.predict(X, batch_size=2048) > 0.5)

            for dataset_file in dataset_filelist:
                filename = dataset_file.split('/')[-1].strip()
                if filename_prefix in filename:
                    X, Y = load_dataset(dataset_file)
                    [packets] = count_packets_in_dataset([X])

                    Y_pred = None
                    Y_true = Y
                    avg_time = 0
                    for iteration in range(iterations):
                        pt0 = time.time()
                        Y_pred = np.squeeze(model.predict(X, batch_size=2048) > 0.5)
                        pt1 = time.time()
                        avg_time += pt1 - pt0

                    avg_time = avg_time / iterations

                    report_results(np.squeeze(Y_true), Y_pred, packets, model_name_string, filename, avg_time,
                                   predict_writer)
                    predict_file.flush()

        predict_file.close()

    if args.predict_live is not None:
        predict_file = open(OUTPUT_FOLDER + 'predictions-' + time.strftime("%Y%m%d-%H%M%S") + '.csv', 'a',
                            newline='')
        predict_file.truncate(0)  # clean the file content (as we open the file in append mode)
        predict_writer = csv.DictWriter(predict_file, fieldnames=PREDICT_HEADER)
        predict_writer.writeheader()
        predict_file.flush()

        if args.predict_live is None:
            print("Please specify a valid network interface or pcap file!")
            exit(-1)
        elif args.predict_live.endswith('.pcap'):
            pcap_file = args.predict_live
            cap = pyshark.FileCapture(pcap_file)
            data_source = pcap_file.split('/')[-1].strip()
        else:
            cap = pyshark.LiveCapture(interface=args.predict_live)
            data_source = args.predict_live

        print("Prediction on network traffic from: ", data_source)

        # load the labels, if available
        labels = parse_labels(args.dataset_type, args.attack_net, args.victim_net)

        # do not forget command sudo ./jetson_clocks.sh on the TX2 board before testing
        if args.model is not None and args.model.endswith('.h5'):
            model_path = args.model
        else:
            print("No valid model specified!")
            exit(-1)

        model_filename = model_path.split('/')[-1].strip()
        filename_prefix = model_filename.split('n')[0] + 'n-'
        time_window = int(filename_prefix.split('t-')[0])
        max_flow_len = int(filename_prefix.split('t-')[1].split('n-')[0])
        model_name_string = model_filename.split(filename_prefix)[1].strip().split('.')[0].strip()
        model = load_model(args.model)

        mins, maxs = static_min_max(time_window)

        while (True):
            samples = process_live_traffic(cap, labels, max_flow_len, traffic_type="all",
                                           time_window=time_window)
            if len(samples) > 0:
                X, Y_true, keys = dataset_to_list_of_fragments(samples)
                X = np.array(normalize_and_padding(X, mins, maxs, max_flow_len))
                if labels is not None:
                    Y_true = np.array(Y_true)
                else:
                    Y_true = None

                X = np.expand_dims(X, axis=3)
                pt0 = time.time()
                Y_pred = np.squeeze(model.predict(X, batch_size=2048) > 0.5, axis=1)
                pt1 = time.time()
                prediction_time = pt1 - pt0

                [packets] = count_packets_in_dataset([X])
                report_results(np.squeeze(Y_true), Y_pred, packets, model_name_string, data_source, prediction_time,
                               predict_writer)
                predict_file.flush()

            elif isinstance(cap, pyshark.FileCapture) == True:
                print("\nNo more packets in file ", data_source)
                break

        predict_file.close()


def report_results(Y_true, Y_pred, packets, model_name, data_source, prediction_time, writer):
    """
    Report results of model predictions including accuracy, F1 score, confusion matrix metrics, and more.

    Args:
        Y_true (numpy array or None): True labels if available, otherwise None.
        Y_pred (numpy array): Predicted labels from the model.
        packets (int): Number of packets processed or data samples used for prediction.
        model_name (str): Name of the model used for prediction.
        data_source (str): Source of the data (e.g., dataset file name or live traffic source).
        prediction_time (float): Time taken for predictions.
        writer (csv.DictWriter): CSV writer object to write results to a CSV file.

    Returns:
        None
    """

    # Calculate DDoS rate as the ratio of positive predictions to total predictions
    ddos_rate = '{:04.3f}'.format(sum(Y_pred) / Y_pred.shape[0])

    if Y_true is not None and len(Y_true.shape) > 0:
        # Compute classification metrics only if true labels are available
        Y_true = Y_true.reshape((Y_true.shape[0], 1))
        accuracy = accuracy_score(Y_true, Y_pred)
        f1 = f1_score(Y_true, Y_pred)

        # Compute confusion matrix metrics (True Negative Rate, False Positive Rate, False Negative Rate,
        # True Positive Rate)
        tn, fp, fn, tp = confusion_matrix(Y_true, Y_pred, labels=[0, 1]).ravel()
        tnr = tn / (tn + fp)
        fpr = fp / (fp + tn)
        fnr = fn / (fn + tp)
        tpr = tp / (tp + fn)

        # Prepare a dictionary row containing various metrics and information
        row = {'Model': model_name, 'Time': '{:04.3f}'.format(prediction_time), 'Packets': packets,
               'Samples': Y_pred.shape[0], 'DDOS%': ddos_rate, 'Accuracy': '{:05.4f}'.format(accuracy),
               'F1Score': '{:05.4f}'.format(f1), 'TPR': '{:05.4f}'.format(tpr), 'FPR': '{:05.4f}'.format(fpr),
               'TNR': '{:05.4f}'.format(tnr), 'FNR': '{:05.4f}'.format(fnr), 'Source': data_source}
    else:
        # Prepare a dictionary row with N/A values for accuracy, F1 score, and confusion matrix metrics
        row = {'Model': model_name, 'Time': '{:04.3f}'.format(prediction_time), 'Packets': packets,
               'Samples': Y_pred.shape[0], 'DDOS%': ddos_rate, 'Accuracy': "N/A", 'F1Score': "N/A",
               'TPR': "N/A", 'FPR': "N/A", 'TNR': "N/A", 'FNR': "N/A", 'Source': data_source}

    # Copy the row for printing, add the predicted labels, and write the row to the CSV file
    row_copy = row.copy()
    row_copy['PREDICT'] = Y_pred  # Include the predicted labels in the printed row
    pprint.pprint(row_copy, sort_dicts=False)  # Print the row with predicted labels included
    writer.writerow(row)  # Write the row to the CSV file

if __name__ == '__main__':
    main()
