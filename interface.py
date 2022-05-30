import tkinter as tk
from tkinter import Label, Toplevel, ttk


def get_label():
    label = uname.get() +" "+ passw.get()
    Label(text=label)

window = tk.Tk()
window.geometry("400x400")
uname_label = Label(text="Segvārds")
uname = tk.Entry()
passw_label = Label(text="Parole")
passw = tk.Entry()
btn_login = tk.Button(text="Login", height=2, width=5, command=get_label)

uname_label.pack()
uname.pack()
passw_label.pack()
passw.pack()
btn_login.pack()
get_label()
window.mainloop()