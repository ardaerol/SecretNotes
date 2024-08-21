from tkinter import *
import base64
from tkinter import messagebox

FONT = ("Verdena",20,"normal")

def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

#save notes and encryt
def save_and_encryt_notes():
    title = title_info_input.get()
    message = title_secret_text.get("1.0",END)
    master_key = master_info_input.get()
    if len(title) == 0 or len(message) == 0 or len(master_key) == 0:
        messagebox.showinfo(title="Error",message="Enter all infermation")
    else:
        message_encryt = encode(master_key,message)
        try:
            with open("mysecret.txt","a") as data_file:
                data_file.write(f"\n{title}\n{message_encryt}")
        except FileNotFoundError:
            with open("mysecret.txt","w") as data_file:
                data_file.write(f"\n{title}\n{message_encryt}")
        finally:
            title_info_input.delete(0,END)
            title_secret_text.delete("1.0",END)
            master_info_input.delete(0,END)

# Decryt
def decryt_notes():
    message_encryt = title_secret_text.get("1.0",END)
    secret_key = master_info_input.get()
    if len(message_encryt) == 0 or len(secret_key) == 0 :
        messagebox.showinfo(title="Error", message="Enter all infermation")
    else:
        try:
            decryt_message = decode(secret_key,message_encryt)
            title_secret_text.delete("1.0",END)
            title_secret_text.insert("1.0",decryt_message)
        except:
                messagebox.showinfo(title="Error!", message="Please make sure of encrypted info.")
#UI
#windows
window = Tk()
window.title("Secret Notes")
window.config(padx=30,pady=30,bg="white")
window.minsize(height=500,width=500)

#LOGO
canvas = Canvas(height=200,width=200,bg="white",bd=0)
logo = PhotoImage(file="topsecret.png")
canvas.create_image(100,100,image=logo)
canvas.pack()

#WİDGETS
title_info_label = Label(text="Enter your title",font=FONT,bg="white",fg="black")
title_info_label.pack()

title_info_input = Entry(width=30,bg="white",fg="black")
title_info_input.pack()

title_secret_label = Label(text="Enter your Secret",font=FONT,bg="white",fg="black")
title_secret_label.pack()

title_secret_text = Text(width=50,height=25,bg="white",fg="black")
title_secret_text.pack()

master_info_label = Label(text="Enter your secret key",font=FONT,bg="white",fg="black")
master_info_label.pack()

master_info_input = Entry(width=30,bg="white",fg="black")
master_info_input.pack()

save_encrytp_btn = Button(text="Save and Encrytp",font=FONT,bg="white",fg="black",command=save_and_encryt_notes)
save_encrytp_btn.pack()

decrytp_btn = Button(text="Decrytp",font=FONT,bg="white",fg="black",bd=0,command=decryt_notes)
decrytp_btn.pack()

window.mainloop()