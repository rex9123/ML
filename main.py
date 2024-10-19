import tkinter as tk
from tkinter import messagebox
import numpy as np
import joblib  # For saving/loading the model
from sklearn.preprocessing import StandardScaler

# Load the trained model and scaler
svm_model = joblib.load('svm_model.pkl')
scaler = joblib.load('scaler.pkl')

def predict():
    try:
        # Get input values
        inputs = [
            float(entry_dur.get()),
            int(entry_proto.get()),
            int(entry_service.get()),
            int(entry_state.get()),
            int(entry_spkts.get()),
            int(entry_dpkts.get()),
            int(entry_sbytes.get()),
            int(entry_dbytes.get()),
            float(entry_rate.get()),
            int(entry_sttl.get()),
            int(entry_dttl.get()),
            float(entry_sload.get()),
            float(entry_dload.get()),
            int(entry_sloss.get()),
            int(entry_dloss.get()),
            int(entry_swin.get()),
            int(entry_dwin.get()),
            int(entry_is_sm_ips_ports.get())
        ]
        
        # Print inputs for debugging
        print("Inputs received:", inputs)
        
        # Scale the input
        inputs_scaled = scaler.transform(np.array(inputs).reshape(1, -1))
        
        # Make prediction
        prediction = svm_model.predict(inputs_scaled)[0]
        result = "Attack" if prediction == 1 else "Normal"
        
        # Display result
        messagebox.showinfo("Prediction Result", f"The predicted label is: {result}")
    except ValueError as e:
        print("Error:", e)  # Print the error message
        messagebox.showerror("Input Error", "Please enter valid values.")


# Create the main window
root = tk.Tk()
root.title("Network Intrusion Detection System")

# Create input fields
input_labels = [
    "Duration (dur)", "Protocol (proto)", "Service (service)", "State (state)",
    "Source Packets (spkts)", "Destination Packets (dpkts)", "Source Bytes (sbytes)",
    "Destination Bytes (dbytes)", "Rate (rate)", "Source TTL (sttl)", "Destination TTL (dttl)",
    "Source Load (sload)", "Destination Load (dload)", "Source Loss (sloss)", 
    "Destination Loss (dloss)", "Source Window (swin)", "Destination Window (dwin)",
    "Symmetric Ports (is_sm_ips_ports)"
]

entries = []
for label in input_labels:
    row = tk.Frame(root)
    lab = tk.Label(row, text=label, width=30)
    ent = tk.Entry(row)
    row.pack(side=tk.TOP, padx=5, pady=5)
    lab.pack(side=tk.LEFT)
    ent.pack(side=tk.RIGHT, expand=tk.YES, fill=tk.X)
    entries.append(ent)

# Save references to entry fields
(entry_dur, entry_proto, entry_service, entry_state, entry_spkts,
 entry_dpkts, entry_sbytes, entry_dbytes, entry_rate, entry_sttl,
 entry_dttl, entry_sload, entry_dload, entry_sloss, entry_dloss,
 entry_swin, entry_dwin, entry_is_sm_ips_ports) = entries

# Create the predict button
button = tk.Button(root, text='Predict', command=predict)
button.pack(side=tk.BOTTOM, padx=5, pady=5)

# Start the GUI loop
root.mainloop()
