import threading
import tkinter as tk
from tkinter import filedialog
from tkinter import ttk
import os
from PIL import Image, ImageTk

from ddos_engine import predict

# Define global variables
global start_screen
global login_screen
global progress_bar
global result_label
global username_entry
global password_entry
global start_button
global selected_file
global select_button
global filename_label
global details_label


#  display the start page
def show_start_page():
    global start_screen
    global start_button
    global progress_bar
    global result_label
    global select_button
    global filename_label
    global details_label

    # Create the start page
    start_screen = tk.Tk()
    start_screen.title("DDoS Detector")
    start_screen.geometry("700x800")

    # Add image to the top of the screen
    start_image = Image.open("logo.png")
    start_image = start_image.resize((200, 150))
    start_photo = ImageTk.PhotoImage(start_image)
    start_image_label = tk.Label(start_screen, image=start_photo)
    start_image_label.image = start_photo
    start_image_label.pack()

    # Create title label
    title_label = tk.Label(start_screen, text="DDOS Attack", font=("Helvetica", 20))
    title_label.pack(pady=10)

    # Create an indeterminate progress bar
    progress_bar = ttk.Progressbar(start_screen, mode="indeterminate")
    progress_bar.pack_forget()

    # Create labels for analysis result and filename
    result_label = tk.Label(start_screen, text="", font=("Helvetica", 12))
    result_label.pack(pady=10)
    filename_label = tk.Label(start_screen, text="", font=("Helvetica", 12), )
    filename_label.pack(pady=10)

    # Create a button to select a file
    select_button = tk.Button(start_screen, text="Select File", command=select_file)
    select_button.pack(pady=10)

    # Create a button to start analysis
    start_button = tk.Button(start_screen, text="Send Request", bg="green", fg="white", command=start_analysis)
    start_button.pack()

    start_screen.mainloop()


#  generate subtitle, quiz, and extract words
def generate():
    global selected_file
    data_list, prediction = predict(selected_file)
    complete_analysis(data_list, prediction)


#  select a file
def select_file():
    global selected_file
    global result_label
    global filename_label
    global details_label
    result_label.config(text="")
    filename_label.config(text="")
    selected_file = filedialog.askopenfilename()
    if selected_file:
        filename_label.config(text=selected_file)


#  start AI analysis
def start_analysis():
    global selected_file
    global progress_bar
    global result_label
    global select_button
    global start_button
    global details_label

    if selected_file:
        result_label.config(text="Sending request")
        select_button.pack_forget()
        start_button.pack_forget()
        progress_bar.pack(pady=10)
        progress_bar.start()  # Start the indeterminate progress bar
        analysis_thread = threading.Thread(target=generate)
        analysis_thread.start()


# Change the labels and hide the progress bar after completed the analysis
def complete_analysis(data_lists, prediction):
    global progress_bar
    global result_label
    global select_button
    global details_label
    global selected_file
    global start_button
    progress_bar.stop()  # Stop the indeterminate progress bar
    progress_bar.pack_forget()
    pred_txt = ""
    malicious = 0
    benign = 0
    for i, each in enumerate(prediction):
        pred_txt += f"The packet {i + 1} from {each[0]} to {each[1]} is {each[2]}\n"
        if each[2] == "NOT a DDOS attack":
            benign += 1
        else:
            malicious += 1
    pred_txt += f"\nTotal: {malicious} Malicious, {benign} Benign\n"
    result_label.config(text=pred_txt)

    if not os.path.exists("details"):
        os.makedirs("details")
    
    with open(f"details/{os.path.split(selected_file)[1]}_details.txt", 'w') as file:
        txt = f"Total: {malicious} Malicious, {benign} Benign\n\n"
        for i, data_list in enumerate(data_lists):
            txt += f"packet {i + 1}:\n " + data_list + f"\nThe packet {i + 1} from {prediction[i][0]} to {prediction[i][1]} is {prediction[i][2]}" + "\n\n\n\n"
        file.write(txt)

    filename_label.config(text=f"Details saved to details/{os.path.split(selected_file)[1]}_details.txt")

    select_button.pack(pady=10)
    select_button.pack()



# build and display the login screen
if __name__ == "__main__":
    show_start_page()
