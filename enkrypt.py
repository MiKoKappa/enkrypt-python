# -*- coding: utf-8 -*-
from tkinter import ttk
import tkinter as tk
import hashlib
from PIL import ImageTk, Image
from cryptography.fernet import Fernet
import os
import re

class Aplikacja(object):
	def __init__(self):
		self.base_path = os.path.abspath(os.path.dirname(__file__))

		self.root = tk.Tk()
		# nazwa aplikacji
		self.nazwa = "enKRYPT"
		self.root.title(self.nazwa)
		# zmiana logo aplikacji
		if("nt" == os.name):
			path = os.path.join(self.base_path, "logo.ico")
			self.root.iconbitmap(path)
		# wielkość okna i pojawianie się na środku ekranu i nieco w górę
		self.root.geometry("600x400+{}+{}".format(int(self.root.winfo_screenwidth()/2 - 600/2), int(self.root.winfo_screenheight()/2 - 400/2)))
		# wyłączenie możliwości zmiany wielkości
		self.root.resizable(False,False)
		self.style = ttk.Style(self.root)

		# ustalenie lokacji źródłowej dla tcl
		path = self.base_path.replace('\\','/')+"/awthemes/"
		self.root.tk.eval("""
		set base_theme_dir """ + path + """ 

		package ifneeded awthemes 10.2.0 \
		    [list source [file join $base_theme_dir awthemes.tcl]]
		package ifneeded colorutils 4.8 \
		    [list source [file join $base_theme_dir colorutils.tcl]]
		package ifneeded awdark 7.11 \
		    [list source [file join $base_theme_dir awdark.tcl]]
		""")
		# załadowanie szablonów stylu
		self.root.tk.call("package", "require", 'awdark')

		# hash wybranego hasła w systemie sha256
		self.dostepHash = "ced1766c41a9013f5c4eefda7e54db6ce67bbb159d8b0dac25ceb35f93433865"

		# klucz dekodujący
		self.key = b'QRHcrO7y_61iDwuOFZ-Syb2zLEUV4xBxDlavVMEbNMA='

		# wybranie stylu dla aplikacji
		self.style.theme_use('awdark')

		self.logowanie()
		# zmiana koloru tła aplikacji na odpowiadający stylowi
		self.root.configure(bg=self.style.lookup('TFrame', 'background'))

		# mainloop aplikacji
		self.root.mainloop()

	def logowanie(self):

		def loguj():
			if(hashlib.sha256(str(loginInput.get()).encode("ascii", "xmlcharrefreplace")).hexdigest()==self.dostepHash):
				logowanie.pack_forget()
				self.root.unbind('<Return>')
				self.aplikacja()
			else:
				blad.pack()
		logowanie = ttk.LabelFrame(self.root, text="LOGOWANIE", labelanchor="nw")
		logowanie.pack(pady=10,padx=10, ipadx=10, ipady=10, anchor="center", expand=True, fill="both")
		blad = ttk.Label(logowanie, text="Błędne hasło!",foreground="red")
		path = os.path.join(self.base_path, "logo.png")
		img = Image.open(path)
		img = img.resize((100,100), Image.ANTIALIAS)
		img = ImageTk.PhotoImage(img)
		image = ttk.Label(logowanie,image=img)
		image.photo = img
		image.pack(pady=(15,0))
		ttk.Label(logowanie, text="Witaj w {}".format(self.nazwa), font=('Helvetica', '17')).pack(pady=(20,10))
		ttk.Label(logowanie, text="Podaj kod dostępu!").pack(pady=(10,0))
		ttk.Label(logowanie, text="Wyk. Mikołaj Tkaczyk, Michał Tański, Krzysztof Gajos", font=("Helvetica", 8)).pack(pady=5, padx=5, anchor="s", side="bottom")
		loginInput = ttk.Entry(logowanie, justify="center", show="*")
		loginInput.pack(pady=10)
		btn = ttk.Button(logowanie, text="OK", command=loguj)
		btn.pack(pady=(0,10))
		self.root.bind('<Return>', lambda e: loguj())
	def aplikacja(self):
		self.counter = 1
		def wylogowywanie():
			wrapper.pack_forget()
			self.logowanie()
		def dodajnowy():
			wrapper.pack_forget()
			self.dodawanie()
		def odswiez():
			wrapper.pack_forget()
			self.aplikacja()
		def decrypt_message(encrypted_message):
			f = Fernet(self.key)
			decrypted_message = f.decrypt(encrypted_message.encode("ascii", "xmlcharrefreplace"))
			decrypted_message = decrypted_message.decode("ascii")
			final_message = ""
			indeksy = [m.start(0) for m in re.finditer(r"&#[0-9]*;", decrypted_message)]
			i = 0
			if(len(indeksy)!=0):
				while(i in range(len(decrypted_message))):
					if(i in indeksy):
						i += 2
						uniletter = ""
						while(decrypted_message[i]!=";"):
							uniletter += decrypted_message[i]
							i += 1
						final_message += chr(int(uniletter))
					else:
						final_message += decrypted_message[i]
					i += 1
			else:
				final_message = decrypted_message
			return final_message
		def decrypt_all():
			path = os.path.join(self.base_path, "hasla.txt")
			if(os.path.getsize(path)==0):
				ttk.Label(scrollable, text="Brak haseł ! :(").pack(side="top", padx=30, pady=100)
			else:
				fp = open(path, "r")
				path = os.path.join(self.base_path, "id.txt")
				fi = open(path, "r")
				for i, k in zip(fp,fi):
					i.rstrip()
					decrypted_message = decrypt_message(i)
					k.rstrip() 
					row = tk.Frame(scrollable, highlightthickness=1, highlightbackground="black", bg=self.style.lookup('TFrame', 'background'))
					row.pack(fill="x", padx=5)
					ttk.Label(row, text=self.counter).pack(side="left", padx=10, pady=3)
					ttk.Label(row, text=k).pack(side="left", padx=10, pady=3)
					ttk.Label(row, text=decrypted_message).pack(side="left", padx=10, pady=3)
					btn = ttk.Button(row, text="X", width=3)
					btn.bind("<Button-1>", lambda e: usun(e.widget.winfo_parent()[e.widget.winfo_parent().find("canvas")+20:]))
					btn.pack(side="right", padx=10, pady=3)
					self.counter+=1
				fp.close()
				fi.close()
		def usun(id):
			path = os.path.join(self.base_path, "id.txt")
			f = open(path, "r")
			lines = f.readlines()
			f.close()
			del lines[int(id)-2]
			f = open(path, "w+")
			for line in lines:
				f.write(line)
			f.close()
			path = os.path.join(self.base_path, "hasla.txt")
			f = open(path, "r")
			lines = f.readlines()
			f.close()
			del lines[int(id)-2]
			f = open(path, "w+")
			for line in lines:
				f.write(line)
			f.close()
			odswiez()
		wrapper = ttk.LabelFrame(self.root, text=self.nazwa+" - Strona głowna", labelanchor="nw")
		wrapper.pack(pady=10,padx=10, ipadx=10, ipady=10, anchor="center", expand=True, fill="both")
		container = tk.Frame(wrapper, bg=self.style.lookup('TFrame', 'background'), highlightthickness=1, highlightbackground="black")
		scrollCanvas = tk.Canvas(container, bg=self.style.lookup('TFrame', 'background'), highlightthickness=0)
		scrollbar = ttk.Scrollbar(container, orient="vertical", command=scrollCanvas.yview)
		scrollable = ttk.Frame(scrollCanvas)
		scrollable.bind("<Configure>", lambda e: scrollCanvas.configure(scrollregion=scrollCanvas.bbox('all')))
		container.pack(fill="x", expand=True, padx=10, pady=10)
		scrollCanvas.pack(side="left", fill="both", expand=True)
		scrollbar.pack(side="right",fill="y")
		self.root.update()
		scrollCanvas.create_window((0,0), window=scrollable, anchor="nw", width=scrollCanvas.winfo_width())
		scrollCanvas.configure(yscrollcommand=scrollbar.set)
		self.style.configure("Vertical.TScrollbar", arrowcolor="#215d9c")
		row = tk.Frame(scrollable, highlightthickness=1, highlightbackground="black", bg=self.style.lookup('TFrame', 'background'))
		row.pack(fill="x", pady=5, padx=5)
		ttk.Label(row, text="ID", state="disabled").pack(side="left", padx=10, pady=3)
		ttk.Label(row, text="Nazwa", state="disabled").pack(side="left", padx=10, pady=3)
		ttk.Label(row, text="Hasło", state="disabled").pack(side="left", padx=10, pady=3)
		ttk.Label(row, text="Usuń", state="disabled").pack(side="right", padx=10, pady=3)
		decrypt_all()
		ttk.Button(wrapper, text="Wyloguj",command=wylogowywanie).pack(padx=5,pady=5,anchor = "s", side = "left")
		ttk.Button(wrapper, text="Dodaj hasło +",command=dodajnowy).pack(padx=5,pady=5,anchor = "s", side = "left")
	def dodawanie(self):
		def newPassword():
			if (passInput.get() == '' or idInput.get() == ''):
				blad.pack(side="top", anchor="n")
				if(passInput.get() == ''):
					passLabel.configure(foreground="red")
				else:
					passLabel.configure(foreground="white")
				if(idInput.get() == ''):
					idLabel.configure(foreground="red")
				else:
					idLabel.configure(foreground="white")
			else:
				path = os.path.join(self.base_path, "hasla.txt")
				fp = open(path, "a")
				path = os.path.join(self.base_path, "id.txt")
				fi = open(path, "a")
				encrypted_message = encrypt_message(passInput.get())
				fp.write(encrypted_message.decode("ascii")+"\n")
				fi.write(idInput.get()+"\n")
				fp.close()
				fi.close()
				dodawanie.pack_forget()
				self.root.unbind('<Return>')
				self.aplikacja()
		def encrypt_message(message):
			encoded_message = message.encode("ascii", "xmlcharrefreplace")
			f = Fernet(self.key)
			encrypted_message = f.encrypt(encoded_message)
			return encrypted_message
		def anuluj():
			dodawanie.pack_forget()
			self.aplikacja()
		dodawanie = ttk.LabelFrame(self.root, text=self.nazwa+" - Dodaj hasło", labelanchor="nw")
		dodawanie.pack(pady=10,padx=10, ipadx=10, ipady=10, anchor="center", expand=True, fill="both")
		ttk.Label(dodawanie, text="Podaj nowe dane!").pack(pady=(80,0))
		container = ttk.Frame(dodawanie)
		container.pack(fill="y", expand=True)
		row1 = ttk.Frame(container)
		row1.pack()
		blad = ttk.Label(container, text="Wypełnij puste pola!",foreground="red")
		idInput = ttk.Entry(row1, justify="center")
		idInput.pack(pady=10, padx=10, side="right")
		idLabel = ttk.Label(row1,text="ID")
		idLabel.pack(pady=10, padx=18, side="left")
		row2 = ttk.Frame(container)
		row2.pack()
		passInput = ttk.Entry(row2, justify="center")
		passInput.pack(pady=10, padx=10, side="right")
		passLabel = ttk.Label(row2,text="Hasło")
		passLabel.pack(pady=10, padx=10, side="left")
		buttonframe = ttk.Frame(container)
		buttonframe.pack(side="top")
		ttk.Button(buttonframe, text="OK", command=newPassword).pack(padx=5,pady=5,anchor = "s", side="left")
		ttk.Button(buttonframe, text="ANULUJ", command=anuluj).pack(padx=5,pady=5,anchor = "s", side="left")
		self.root.bind('<Return>', lambda e: newPassword())

def main():
	a = Aplikacja()

main()