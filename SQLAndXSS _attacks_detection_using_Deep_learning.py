import time
import subprocess
import pandas as pd
import urllib.parse as urlenc
from collections import Counter
from tensorflow.keras import layers
from pandas import DataFrame
from tensorflow import keras
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences

"""
This model can detect sql injection and XSS attack by monitoring the log file for the appach server
Notes
1-we take all of the the data as a training
2-we tested on the log file on appach server by building login form for the testing

"""
# read training data
df = pd.read_csv('training_dataset.csv')
rdf = ''


def counter_word(text_col):
    count = Counter()
    for text in text_col.values:
        for word in text.split():
            count[word] += 1
    return count


def clean_the_request(raw_data):
    space_pluse_data = urlenc.unquote(raw_data)
    cleaned_data = urlenc.unquote_plus(space_pluse_data)
    return cleaned_data


"""
-We tested the model by reading requests in the access.log , 
the model can distinguish between malicious requests like sql injection , XSS attack.
If the model detect malicious request , we take an action by disabling the internet for the appach server
"""


def test_data():
    global rdf
    request = ''

    with open("C:\\xampp\\apache\\logs\\access.log", 'r+') as log_file:
        request = log_file.readlines()[-1].rstrip()
        log_file.close()
    try:
        string = request.split(' ')[6].split('?')[1].split('&')[1].split('=')[1]
        list = {'text': string, 'target': [0]}
        rdf = DataFrame(list)

        test_df = rdf
        test_sentences = test_df.text.to_numpy()
        test_sequences = tokenizer.texts_to_sequences(test_sentences)
        test_padded = pad_sequences(test_sequences, maxlen=max_length, padding="post", truncating="post")

        predictions = model.predict(test_padded)
        predictions = [1 if p > 0.5 else 0 for p in predictions]

        if predictions[0] == 1:
            diswifi = subprocess.run(["netsh", "interface", "set", "interface", "Wi-Fi", "disabled"])
            print("ATTACK!!! => >( " + clean_the_request(string) + ' )<')
            print("Failed to disable wifi" if diswifi.returncode else "Wifi disabled")

            time.sleep(5)
            subprocess.run(["netsh", "interface", "set", "interface", "Wi-Fi", "enabled"])
            return 1
        else:
            print("Normal.")
    except Exception:
        pass

# prepare the dataset for training

counter = counter_word(df.text)
num_unique_words = len(counter)

train_df = df

train_sentences = train_df.text.to_numpy()
train_labels = train_df.target.to_numpy()

tokenizer = Tokenizer(num_words=num_unique_words)
tokenizer.fit_on_texts(train_sentences)
train_sequences = tokenizer.texts_to_sequences(train_sentences)
max_length = 20
train_padded = pad_sequences(train_sequences, maxlen=max_length, padding="post", truncating="post")
# LSTM algorithm used to training the data
model = keras.models.Sequential()
model.add(layers.Embedding(num_unique_words, 32, input_length=max_length))
model.add(layers.LSTM(64, dropout=0.1))
model.add(layers.Dense(1, activation="sigmoid"))
loss = keras.losses.BinaryCrossentropy(from_logits=False)
optim = keras.optimizers.Adam(learning_rate=0.001)
metrics = ["accuracy"]

model.summary()

model.compile(loss=loss, optimizer=optim, metrics=metrics)
model.fit(train_padded, train_labels, epochs=1, verbose=2)

while True:
    if test_data():
        break
