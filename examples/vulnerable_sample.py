import os
import sqlite3


def run_command():
    command = input("command: ")
    os.system(command)


def find_user():
    username = input("username: ")
    connection = sqlite3.connect("app.db")
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '" + username + "'")
    return cursor.fetchall()


def read_file():
    filename = input("filename: ")
    with open(filename, "r", encoding="utf-8") as file:
        return file.read()
