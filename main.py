import base64
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import random
import string
import pyautogui
import time
import numexpr
from tqdm import tqdm
import getpass
import configparser
import os
from Exceptions import *
from QRCodeManager import *
import json
import uuid

class config():
    """
    Manages configuration file, might change it later.
    """
    def __init__(self, user: str):
        self.file = 'config.ini'
        self.user = user

    def checkUserExists(self):
        config = configparser.ConfigParser()
        config.read('config.ini')
        return self.user in config

    def readUserSalt(self):
        return self.getData('salt')

    def readUserPassword(self):
        return self.getData('password')

    def getData(self, arg0):
        config = configparser.ConfigParser()
        config.read('config.ini')
        return config[self.user][arg0]

    def add(self, password: str, force: bool = False):
        salt = str(random.randint(1, 100))
        if not(os.path.exists("config.ini")):
            config = configparser.ConfigParser()
        else:
            config = configparser.ConfigParser()
            config.read('config.ini')
            if self.user in config and not force:
                raise UserAlreadyWithPassword

        config[self.user] = {'password': hashSHA512(password + salt), 'salt': salt}
        with open('config.ini', 'w') as file:
            config.write(file)

class passwordManagerFile():
    """
    Manages password files, not finished yet.
    """
    def __init__(self, user: str):
        """Creates or reads json"""
        self.file = user + '.json'
        try:
            try:
                with open(self.file, 'rb') as file: 
                    self.json = json.load(file)
            except json.decoder.JSONDecodeError:
                self.key = readQRCode()
                fileED(self.file, self.key).decrypt()
                with open(self.file, 'rb') as file: 
                    self.json = json.load(file)
        except FileNotFoundError:
            with open(self.file, 'w') as file:
                self.json = {"examplename": "examplepassword"}
                json.dump(self.json, file, indent = 2)
    
    def add(self, name: str, password: str):
        """Adds password to json file"""
        data = {name: password}
        self.json.update(data)
        with open(self.file, 'w') as file:
            json.dump(self.json, file, indent = 2)

    def read(self, name: str):
        return self.json[name]
    
    def close(self):
        fileED(self.file, self.key)

def generateEquation():
    """Generates random password encryption equation."""
    elements = ["time_now", "seed_num_1", "seed_num_2", "mouse_sum"]
    equations = ["+", "-", "*", "/"]
    result = "".join(
        random.choice(equations) if i % 2 == 0 else random.choice(elements)
        for i in range(1, random.randint(1, 100))
    )
    if result.endswith(tuple(equations)):
        result = result[:-1]
    return result

def generateSeed(reason: str, reqMove = 10000):
    print(f"Collecting mouse movement for {reason}, move your mouse as random as you can until progress bar will be full")
    old_x, old_y = pyautogui.position()
    x_sum = 0
    y_sum = 0
    mouse_sum = 0
    i = 0
    random.seed(uuid.uuid4())
    with tqdm(total = reqMove, leave=False) as pbar:
        while i <= reqMove:
            if old_x != pyautogui.position()[0] or old_y != pyautogui.position()[1]:
                old_x_sum, old_y_sum = pyautogui.position()
                x_sum += old_x_sum
                y_sum += old_y_sum
                i += 1
                pbar.update(1)
    for _ in range(1, 5):
        eq = random.choice(["x_sum/y_sum", "y_sum/x_sum", "x_sum*y_sum", "x_sum+y_sum", "x_sum-y_sum", "y_sum-x_sum"])
        mouse_sum += numexpr.evaluate(eq).item()
    seed_num_1 = random.randint(1, 100)
    seed_num_2 = random.randint(1, 1000000)
    time_now = time.time()
    equation = generateEquation()
    seed = numexpr.evaluate(equation)
    seed_b = '%.30f'%seed
    seed_b = seed_b.encode()
    return seed_b

def hashSHA512(data: str):
    return hashlib.sha512(data.encode("utf-8")).hexdigest()

def derive(psk: str, session_salt: bytes):
    kdf = Scrypt(salt=session_salt,
                    length=32,
                    n=2**14,
                    r=8,
                    p=1)
    try:
        key = kdf.derive(psk.encode())
    except AttributeError:
        key = kdf.derive(psk)
    key = base64.urlsafe_b64encode(key)
    return key

def generateKeyFromPassword(password: str):
    return derive(hashSHA512(password), hashSHA512(password).encode())

def encryptData(data: bytes, key):
    f = Fernet(key)
    return f.encrypt(data)

def decryptData(data: bytes, key):
    f = Fernet(key)
    return f.decrypt(data)

class fileED():
    """
    Encrypts and decrypts files.
    """
    def __init__(self, file, key):
        self.file = file
        self.key = key

    def encrypt(self):
        with open(self.file, 'rb') as dataFile:
            data = dataFile.read()
        encrypted = encryptData(data, self.key)
        with open(self.file, 'wb') as encryptedFile:
            encryptedFile.write(encrypted)
    
    def decrypt(self):
        with open(self.file, 'rb') as encryptedFile:
            data = encryptedFile.read()
        decrypted = decryptData(data, self.key)
        with open(self.file, 'wb') as decryptedFile:
            decryptedFile.write(decrypted)

def generatePassword(length: int, reason: str):
    acceptable = string.ascii_letters + string.digits + string.punctuation
    rounds = random.randint(1, 1000000)
    reqMove = 5000
    if reason != "Password Encryption Password":
        if length < 15:
            reqMove = 10 + length * 200
        if length > 50:
            reqMove = length * 100
        if length >= 15 and length <= 50:
            reqMove = length * 200
    random.seed(generateSeed(reason, reqMove))
    for _ in range(rounds + random.randint(1, 100)):
        random.choice(acceptable)
    passwordList = [random.choice(acceptable) for _ in range(length)]
    password = ''
    password = password.join(passwordList)
    if password.startswith('b"'):
        password = generatePassword(length, "regenerating password due to an error")
    return password

def generateUserSeed(file: str):
    userSeed = generateSeed("user seed (first start)")
    generateQRCode(file, userSeed)
    return userSeed

def generatePEP(file: str): # PEP - Password Encryption Password
    pep = generatePassword(64, "Password Encryption Password")
    generateQRCode(file, pep)
    return pep

class User():
    def __init__(self, user, password = None):
        self.user = user
        self.password = password

    def checkUser(self):
        userData = config(self.user)
        check = userData.checkUserExists()
        return bool(check)

    def checkPassword(self):
        userData = config(self.user)
        if not self.password:
            raise NoPasswordGiven
        try:
            salt = userData.readUserSalt()
            hash = hashSHA512(self.password + salt)
            savedHash = userData.readUserPassword()
            if hash != savedHash:
                return False
        except KeyError:
            pass
        return True

    def new(self):
        if User.checkUser(self):
            raise UserAlreadyExists
        try:
            User.checkPassword(self)
        except NoPasswordGiven:
            raise NoPasswordGiven
        print("New User")
        config(self.user).add(self.password)
        print("Generating seed QR code, it is used to decrypt file with passwords, losing it will result in losing access to passwords")
        generateUserSeed(self.user + ".png")

    def newPassword(self, name: str, length: int):
        if not(User.checkUser(self)):
            raise UserNotFound
        try:
            if not(User.checkPassword(self)):
                raise WrongPassword
        except NoPasswordGiven:
            raise NoPasswordGiven
        pep = generatePEP(name + ".png")
        salt = generateKeyFromPassword(self.password)
        cleanPassword = generatePassword(length, "creating password for {}".format(name))
        typer(cleanPassword)
        password = encryptData(cleanPassword.encode(), derive(pep, salt))
        cleanPassword = random.random()
        passwordManagerFile(self.user).add(name, password.decode())

    def readPassword(self, name: str):
        if not(User.checkUser(self)):
            raise UserNotFound
        try:
            if not(User.checkPassword(self)):
                raise WrongPassword
        except NoPasswordGiven:
            raise NoPasswordGiven
        pep = readQRCode()
        salt = generateKeyFromPassword(self.password)
        encryptedPassword = passwordManagerFile(self.user).read(name)
        return decryptData(encryptedPassword.encode(), derive(pep, salt))

def typer(password, intro = False):
    if not(intro):
        print("Program will now type out password for you, you have 5 seconds to select place where you need to input password. Type Yes/yes (accepts only that) to confirm.")
        confirm = input("Yes: ")
    else:
        confirm = "Yes"
    try:
        while confirm in ["Yes", "yes"]:
            time.sleep(5)
            password = str(password)
            if password.startswith('b"'):
                password = password[2:]
                password = password[:-1]
            pyautogui.write(str(password), interval=0.01)
            print("Repeat? (Use in 'Repeat Password' fields)? Type Yes/yes (accepts only that) to confirm. You will again get 5 seconds to select place to input password.")
            confirm = input("Yes: ")
    except KeyboardInterrupt:
        pass

def temporaryMenu(user: str, password: str):
    print("This is temporary menu made for testing, currently encryption of passwords isn't fullly finished. Only use if you know what you are doing.")
    manager = User(user, password)
    if not(manager.checkUser()):
        manager.new()
    if not(manager.checkPassword()):
        raise WrongPassword()
    while True:
        print(
            "1. Gen password",
            "2. Read password",
            "0. Exit"
        )
        dec = int(input(": "))
        if dec == 1:
            name = input("Name: ")
            length = int(input("Length: "))
            manager.newPassword(name, length)
        elif dec == 2:
            name = input("Name: ")
            typer(manager.readPassword(name))
        else:
            exit()

if __name__ == '__main__':
    user = input("User: ")
    password = getpass.getpass(prompt = "Password: ")
    try:
        temporaryMenu(user, password)
    except WrongPassword:
        print("Wrong password")