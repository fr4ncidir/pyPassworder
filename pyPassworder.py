#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  pyPassworder.py
#  
#  Copyright 2021 Francesco Antoniazzi <francesco.antoniazzi1991@gmail.com>
#  
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#  
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#  
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.
#  
#  

import sys
import yaml
import logging

from os import getcwd, rename, remove
from os.path import normpath, join, split, getsize, isfile
from shutil import copyfile
from threading import Thread, Event
from time import sleep

from tkinter import Scrollbar, Tk, Menu, Button, Label, filedialog, messagebox, Text, simpledialog
from tkinter.ttk import Combobox
from tkinter.constants import *
from base64 import urlsafe_b64encode
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# Application constants
logging.basicConfig(level=logging.DEBUG, format="%(levelname)s   %(asctime)-15s %(filename)s[%(lineno)d] : %(message)s")
APPLICATION = "pyPassworder"

# GUI constants
SIZE_X = 800
SIZE_Y = 400
BORDER = 10
HEIGHT = 30
COL_B_WIDTH = SIZE_X/3-3*BORDER
TEXT = "text"
ERROR = "Error!"
BEGIN = "1.0"
PASSWORD = "Password"
HIDE_PW_CHAR = "*"
FILETYPES = [("Yaml file", "*.yaml"), ("all files", "*.*")]

# GUI variables
root = None                 # Tk root
fileLabel = None            # label where the yaml password file path is stored
yamlChoice = None           # combobox for yaml keys
resultText = None
timeLabel = None
cleanUpEvent = Event()

def information():
    logging.debug("Requested information")
    messagebox.showinfo(title="Information", message=APPLICATION + """    
Copyright 2021 
Francesco Antoniazzi <francesco.antoniazzi1991@gmail.com>

Black lives matter.
Love is love.

Please consider donating to https://www.ail.it/
""")

def version():
    logging.debug("Requested version")
    messagebox.showinfo(title="Version", message=APPLICATION + """
Version 1.0
Released on 24 Jan 2021
Francesco Antoniazzi <francesco.antoniazzi1991@gmail.com>

Released under GPL 2.0

https://github.com/fr4ncidir/pyPassworder
""")

def _isBlank(text):
    return ((not text) or text.isspace())

def chooseYamlFile(yamlFile=None):
    global yamlChoice

    yamlFilePath = None
    try:
        if yamlFile is None:
            yamlFile = filedialog.askopenfile(
                initialdir = getcwd(), 
                title = "Select a Password File", 
                filetypes = FILETYPES)
        elif yamlFile and isfile(yamlFile):
            yamlFile = open(yamlFile, "r")
        else:
            logging.warning(f"Empty yaml file: {yamlFile}")
            return
        
        yamlFilePath = normpath(yamlFile.name)
        logging.debug(f"Requested yaml file: {yamlFilePath}")
        fileLabel.config(text=yamlFilePath)
        if getsize(yamlFilePath) > 0:
            yamlKeys = list(yaml.load(yamlFile, Loader=yaml.SafeLoader).keys())
            yamlChoice.config(values=yamlKeys)
        else:
            yamlChoice.config(values=[])
        yamlFile.close()
    except Exception as e:
        errorMsg = f"Error while opening '{yamlFilePath}' due to: {repr(e)}"
        logging.error(errorMsg)
        messagebox.showerror(title=ERROR, message=errorMsg)

def getYamlFilePathOrDefault(default=None):
    if ((fileLabel is None) or (_isBlank(fileLabel[TEXT]))):
        result = default if (default and isfile(default)) else ""
        logging.debug(f"Default yaml path: {result}")
        return result
    else:
        logging.debug(f"Requested yaml file path: {fileLabel[TEXT]}")
        return fileLabel[TEXT]

def fillResult(originContent, key=None):
    global resultText
    try: 
        if not _isBlank(key):
            with open(originContent, "r") as yamlFile:
                yamlContent = yaml.load(yamlFile, Loader=yaml.SafeLoader)
                contents = "" if not key in yamlContent else yamlContent[key]
        else:
            contents = originContent
        resultText.delete(BEGIN, END)
        resultText.insert(BEGIN, contents)
    except Exception as e:
        errorMsg = f"Error while showing contents from '{originContent}, {key}' due to: {repr(e)}"
        logging.error(errorMsg)
        messagebox.showerror(title=ERROR, message=errorMsg)

def getKey(pw):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), 
        length=32, 
        salt=b'y\x94\xc49`\x18\xb2\xb0Q\xf7\x1ed\x7f*lO', 
        iterations=100000)
    key = urlsafe_b64encode(kdf.derive(pw.encode()))
    return Fernet(key)

def decrypt():
    global resultText
    global timeLabel
    global cleanUpEvent

    if cleanUpEvent.is_set():
        cleanUpEvent.clear()
    
    fillResult(fileLabel[TEXT], yamlChoice.get())
    content = resultText.get(BEGIN, END)
    if _isBlank(content):
        logging.info("No content to decrypt")
        return
    
    pw = simpledialog.askstring(PASSWORD, "Enter Password:", show=HIDE_PW_CHAR)
    if _isBlank(pw):
        logging.info("Empty password")
        return
    
    try:
        key = getKey(pw)
        result = key.decrypt(content.encode()).decode()
        fillResult(result)
    except Exception as e:
        errorMsg = f"Unable to decrypt: {repr(e)}"
        logging.error(errorMsg)
        messagebox.showerror(title=ERROR, message=errorMsg)
        return
    
    def waitAndErase():
        cleanUpEvent.set()
        for i in range(30, 0, -1):
            if not cleanUpEvent.is_set():
                timeLabel[TEXT] = ""
                return
            timeLabel[TEXT] = f"Timer: {str(i)}"
            if i % 3 == 0:
                logging.warning(timeLabel[TEXT])
            sleep(1)
        fillResult("")
        timeLabel[TEXT] = ""
    t = Thread(target=waitAndErase)
    t.start()
    logging.debug("Started waitAndErase thread")

def _clearText():
    global cleanUpEvent
    fillResult("")
    cleanUpEvent.clear()

def encrypt():
    content = resultText.get(BEGIN, END)
    if _isBlank(content):
        logging.info("Empty content to encrypt")
        return

    id = simpledialog.askstring("Password ID", "Please provide password identifier")
    if _isBlank(id):
        logging.info("Empty password")
        return
    if id in yamlChoice["values"]:
        errorMsg = f"Id '{id}' is already in the file. Please remove the entry manually, if you want to proceed with this ID"
        logging.error(errorMsg)
        messagebox.showerror(title=ERROR, message=errorMsg)
        return

    epw = simpledialog.askstring(PASSWORD, "Enter Encryption Password:", show=HIDE_PW_CHAR)
    if _isBlank(epw):
        logging.info("Empty password")
        return

    (h, t) = split(fileLabel[TEXT])
    temp_filepath = "{}/TEMP_{}".format(h,t)
    copyfile(fileLabel[TEXT], temp_filepath)
    try:
        key = getKey(epw)
        encrypted = key.encrypt(content.encode()).decode()
        out_file = open(fileLabel[TEXT], "a")
        out_file.write(f"{id.lower()}:\n    {encrypted}\n")
        out_file.close()
    except Exception as e:
        remove(fileLabel[TEXT])
        rename(temp_filepath, fileLabel[TEXT])
        errorMsg = "Unable to encrypt"
        logging.error(errorMsg)
        messagebox.showerror(title=id, message=errorMsg)
        return
    fillResult(encrypted)
    remove(temp_filepath)

def new_password_file():
    filepath = filedialog.asksaveasfilename(title = "Please provide a file name",
        filetypes = FILETYPES,
        initialdir = getcwd())  
    if _isBlank(filepath):
        logging.info("Empty filePath")
        return
    
    try:
        f = open(filepath, "x")
        f.close()
    except FileExistsError:
        warnMsg = "This file already exists!"
        logging.warning(warnMsg)
        messagebox.showwarning(message=warnMsg)
    chooseYamlFile(filepath)

def _openYamlFile(yamlPath):
    if not _isBlank(yamlPath) and isfile(yamlPath):
        logging.debug(f"Will try to open {yamlPath} in default editor")
        try:
            if sys.platform == "win32":
                from os import startfile
                startfile(normpath(yamlPath))
            else:
                from subprocess import call
                opener = "open" if sys.platform == "darwin" else "xdg-open"
                call([opener, normpath(yamlPath)])
        except Exception as e:
            errorMsg = f"Unable to open file {yamlPath} in external editor due to {repr(e)}"
            logging.error(errorMsg)
            messagebox.showerror(title=ERROR, message=errorMsg)
    else:
        warnMsg = "No file to open!"
        logging.warning(warnMsg)
        messagebox.showwarning(message=warnMsg)

def main(args):
    global root
    global fileLabel
    global yamlChoice
    global resultText
    global timeLabel

    root = Tk()
    root.title(APPLICATION)
    root.geometry(f"{SIZE_X}x{SIZE_Y}")
    root.resizable(width=False, height=False)
    
    menu = Menu(root, tearoff=0)
    fileMenu = Menu(menu, tearoff=0)
    fileMenu.add_command(label="New password file", command=new_password_file)
    fileMenu.add_command(label="Exit", command=root.quit)
    about = Menu(menu, tearoff=0)
    about.add_command(label="Info", command=information)
    about.add_command(label="Version", command=version)
    menu.add_cascade(label="File", menu=fileMenu)
    menu.add_cascade(label="About", menu=about)
    root.config(menu=menu)

    fileLabel = Label(root, text=getYamlFilePathOrDefault(default=normpath(join(getcwd(), "passwords.yaml"))), 
        borderwidth=2, relief="ridge")
    fileLabel.place(x=BORDER, y=BORDER, width=(SIZE_X-BORDER)*3/4, height=HEIGHT)
    
    fileButton = Button(root, text="Password File...", command=chooseYamlFile)
    fileButton.place(x=2*BORDER+(SIZE_X-BORDER)*3/4, y=BORDER, 
        width=(SIZE_X-3*BORDER-(SIZE_X-BORDER)*3/4), height=HEIGHT)

    yamlChoice = Combobox(root, state="readonly")
    yamlChoice.place(x=BORDER, y=2*BORDER+HEIGHT, width=(SIZE_X-BORDER)*3/4, height=HEIGHT)
    chooseYamlFile(yamlFile=getYamlFilePathOrDefault())
    yamlChoice.bind("<<ComboboxSelected>>", lambda x: fillResult(fileLabel[TEXT], yamlChoice.get()))
    openButton = Button(root, text="Open File in default editor", command=lambda: _openYamlFile(fileLabel[TEXT]))
    openButton.place(x=2*BORDER+(SIZE_X-BORDER)*3/4, y=2*BORDER+HEIGHT, 
        width=(SIZE_X-3*BORDER-(SIZE_X-BORDER)*3/4), height=HEIGHT)

    resultText = Text(root)
    resultText.place(x=BORDER, y=3*BORDER+2*HEIGHT, height=SIZE_Y-5*BORDER-2*HEIGHT, width=2/3*SIZE_X)
    scroll = Scrollbar(resultText)
    scroll.pack(side=RIGHT, fill=Y)
    scroll.config(command=resultText.yview)
    resultText.config(yscrollcommand=scroll.set)

    decryptButton = Button(root, text="Decrypt", command=decrypt)
    decryptButton.place(x=2*BORDER+2/3*SIZE_X, y=3*BORDER+2*HEIGHT, 
        width=COL_B_WIDTH, height=HEIGHT)

    encryptButton = Button(root, text="Encrypt", command=encrypt)
    encryptButton.place(x=2*BORDER+2/3*SIZE_X, y=4*BORDER+3*HEIGHT, 
        width=COL_B_WIDTH, height=HEIGHT)

    clearButton = Button(root, text="Clear text", command=_clearText)
    clearButton.place(x=2*BORDER+2/3*SIZE_X, y=5*BORDER+4*HEIGHT, 
        width=COL_B_WIDTH, height=HEIGHT)

    timeLabel = Label(root, text="")
    timeLabel.place(x=2*BORDER+2/3*SIZE_X, y=6*BORDER+5*HEIGHT, width=COL_B_WIDTH, height=HEIGHT)

    root.mainloop()
    return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv))