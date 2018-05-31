from tkinter import *
import tkinter.messagebox
from tkinter.filedialog import askopenfilename
from pydes import des
from AES import AESCipher
from chilkat import chilkat

key = ""
crypt = chilkat.CkCrypt2()
success = crypt.UnlockComponent("Anything for 30-day trial")
if (success != True):
    print(crypt.lastErrorText())
    sys.exit()

opciones = ['DES','3DES','AES']
nombre_archivo_e2 = ""

root = Tk()
root.title("Cifrado Simetrico")
root.geometry('460x150')

var = StringVar(root)
var.set('DES')

var_check1 = IntVar()
var_check2 = IntVar()

label_1 = Label(root, text="Elegir:")
label_2 = Label(root, text="Método:")
label_3 = Label(root, text="Archivo (con extensión):")


label_4 = Label(root, text="Llave:")
label_5 = Label(root, text="Cifrar")
label_6 = Label(root, text="Descifrar")

opcion = OptionMenu(root, var, *opciones)
cifrar_descifrar = Button(root, text="Cifrar/Descifrar")

def abrirarchivo(event):
    entry_2.delete(0,END)
    nombre_archivo_e2 = askopenfilename(filetypes=(("TXT files", "*.txt"),("All files", "*.*")))
    entry_2.insert(0,nombre_archivo_e2)

entry_1 = Entry(root)
entry_2 = Entry(root)
entry_2.bind("<Button-1>", abrirarchivo)
entry_1.config(show="*");

c_1 = Checkbutton(root, text="Cifrar", variable=var_check1)
c_2 = Checkbutton(root, text="Descifrar", variable=var_check2)

label_1.grid(row=0)
label_2.grid(row=0, column=1)
c_1.grid(row=1, column=1)
c_2.grid(row=1, column=2)
opcion.grid(row=1, column=0)
label_4.grid(row=2, column=0)
entry_1.grid(row=3, column=0)

label_3.grid(row=2, column=2)
entry_2.grid(row=3, column=2)

cifrar_descifrar.grid(row=5, column=1)

"""CIFRADO DES"""
def cifrarDES():
    key = entry_1.get()
    name_file = entry_2.get()
    file = open(name_file, 'r')
    text = file.read()
    d = des()
    ciphered = d.encrypt(key,text,padding=True)
    file = open('msjCifradoDES.txt','w') 
    file.write(ciphered)
    file.close()
    print ("Cifrado DES: %r" % ciphered)

def descifrarDES():
    key = entry_1.get()
    name_file = entry_2.get()
    file = open(name_file, 'r')
    text = file.read()
    d = des()
    plain = d.decrypt(key,text,padding=True)
    file = open('msjDescifradoDES.txt','w') 
    file.write(plain)
    file.close()
    print ("Descifrado DES: ", plain)

"""CIFRADO TRIPLE DES"""
def encrypt3DES():
    """algoritmo"""
    crypt = chilkat.CkCrypt2()
    crypt.put_CryptAlgorithm("3des")    
    crypt.put_CipherMode("cbc")
    crypt.put_KeyLength(192)
    crypt.put_PaddingScheme(0)
    crypt.put_EncodingMode("hex")
    ivHex = "0001020304050607"
    crypt.SetEncodedIV(ivHex,"hex")
    """algoritmo"""
    keyHex = entry_1.get()
    name_file = entry_2.get()
    file = open(name_file, 'r')
    text = file.read()
    crypt.SetEncodedKey(keyHex,"hex")
    plain = crypt.encryptStringENC(text)
    file = open('msjCifrado3DES.txt','w') 
    file.write(plain)
    file.close()
    print("Cifrado 3DES: ", plain)

def decrypt3DES():
    """algoritmo"""
    crypt = chilkat.CkCrypt2()
    crypt.put_CryptAlgorithm("3des")    
    crypt.put_CipherMode("cbc")
    crypt.put_KeyLength(192)
    crypt.put_PaddingScheme(0)
    crypt.put_EncodingMode("hex")
    ivHex = "0001020304050607"
    crypt.SetEncodedIV(ivHex,"hex")
    """algoritmo"""
    keyHex = entry_1.get()
    name_file = entry_2.get()
    file = open(name_file, 'r')
    text = file.read()
    crypt.SetEncodedKey(keyHex,"hex")
    plain = crypt.decryptStringENC(text)
    file = open('msjDescifrado3DES.txt','w') 
    file.write(plain)
    file.close()
    print("Descifrado 3DES: ", plain)

"""CIFRADO AES"""
def cifrarAES():
    key = entry_1.get()
    name_file = entry_2.get()
    file = open(name_file, 'r')
    text = file.read()
    aes = AESCipher(key)
    textCifradoAES = aes.encrypt(text)
    file = open('msjCifradoAES.txt','w') 
    file.write(textCifradoAES.decode('utf-8'))
    file.close()
    print ("Cifrado AES: ", textCifradoAES)

def descifrarAES():
    key = entry_1.get()
    name_file = entry_2.get()
    file = open(name_file, 'r')
    text = file.read()
    aes = AESCipher(key)
    textCifradoAES = aes.decrypt(text)
    file = open('msjDescifradoAES.txt','w') 
    file.write(textCifradoAES)
    file.close()
    print ("Descifrado AES: ", textCifradoAES)

def main(event):
    if var.get() == "DES":
        if var_check1.get() == 1 and var_check2.get() == 0: #cifrar
            if entry_1.get() == "": #valida que contenga una llave
                tkinter.messagebox.showerror("Entrada no valida", "Introduce una llave para continuar")
            else:
                cifrarDES()
                tkinter.messagebox.showinfo("Mensaje Cifrado (DES) con exito", "Mensaje almacenado en el archivo msjCifradoDES.txt")
                entry_2.delete(0,END)
        elif var_check1.get() == 0 and var_check2.get() == 1: #descifrar
            if entry_1.get() == "": #valida que contenga una llave
                tkinter.messagebox.showerror("Entrada no valida", "Introduce una llave para continuar")
            else:
                descifrarDES()
                tkinter.messagebox.showinfo("Mensaje Descifrado (DES) con exito", "Mensaje almacenado en el archivo msjDescifradoDES.txt")
                entry_2.delete(0,END)
        elif var_check1.get() == 1 and var_check2.get() == 1: #error
            tkinter.messagebox.showerror("Comando Erroneo", "Desactiva cualquier casilla para continuar")
    
    elif var.get() == "3DES":
        if var_check1.get() == 1 and var_check2.get() == 0: #cifrar
            if entry_1.get() == "": #valida que contenga una llave
                tkinter.messagebox.showerror("Entrada no valida", "Introduce una llave para continuar")
            else:
                encrypt3DES()
                tkinter.messagebox.showinfo("Mensaje Cifrado (3DES) con exito", "Mensaje almacenado en el archivo msjCifrado3DES.txt")
                entry_2.delete(0,END)
        elif var_check1.get() == 0 and var_check2.get() == 1: #descifrar
            if entry_1.get() == "": #valida que contenga una llave
                tkinter.messagebox.showerror("Entrada no valida", "Introduce una llave para continuar")
            else:
                decrypt3DES()
                tkinter.messagebox.showinfo("Mensaje Descifrado (3DES) con exito", "Mensaje almacenado en el archivo msjDescifrado3DES.txt")
                entry_2.delete(0,END)
        elif var_check1.get() == 1 and var_check2.get() == 1: #error
            tkinter.messagebox.showerror("Comando Erroneo", "Desactiva cualquier casilla para continuar")
    
    elif var.get() == "AES":
        if var_check1.get() == 1 and var_check2.get() == 0: #cifrar
            if entry_1.get() == "": #valida que contenga una llave
                tkinter.messagebox.showerror("Entrada no valida", "Introduce una llave para continuar")
            else:
                cifrarAES()
                tkinter.messagebox.showinfo("Mensaje Cifrado (AES) con exito", "Mensaje almacenado en el archivo msjCifradoAES.txt")
                entry_2.delete(0,END)
        elif var_check1.get() == 0 and var_check2.get() == 1: #descifrar
            if entry_1.get() == "": #valida que contenga una llave
                tkinter.messagebox.showerror("Entrada no valida", "Introduce una llave para continuar")
            else:
                descifrarAES()
                tkinter.messagebox.showinfo("Mensaje Descifrado (AES) con exito", "Mensaje almacenado en el archivo msjDescifradoAES.txt")
                entry_2.delete(0,END)
        elif var_check1.get() == 1 and var_check2.get() == 1: #error
            tkinter.messagebox.showerror("Comando Erroneo", "Desactiva cualquier casilla para continuar")
        
cifrar_descifrar.bind("<Button-1>", main)
root.mainloop()