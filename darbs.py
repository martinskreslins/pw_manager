import base64
import mysql.connector
import logging
import os.path
from cryptography.fernet import Fernet
from configparser import ConfigParser
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

logging_format_string = "%(levelname)s %(asctime)s - %(message)s"
logging.basicConfig(filename=".\\logs\\logfile.log", level=logging.DEBUG,
                    format=logging_format_string, encoding="UTF-8")
logger = logging.getLogger()

logger.debug("# Programma startēta.")

# Izveido konfiguracijas failu ja tāda nav.
def init_config():
    logger.info("#init_config() Izveido konfiguracijas failu, ja tāda nav.")
    file_exists = os.path.exists('config.ini')
    global config_file
    config_file = ConfigParser()
    if (file_exists == False):
        config_file["DATABASECONFIG"] = {
            "host": "localhost", "database": "kontu_dati", "user": "enduser", "passwd": "enduser"}
        config_file["KEYCONFIG"] = {"salt": "unset_salt"}
        with open('config.ini', 'w') as conf:
            config_file.write(conf)

# izveido datubazi, lai ar kursoru varetu izvedot sql pieprasijumu
def init_db_template():
    logger.info(
        "init_db_template() Izveido datu bāzes mainīgo, lai varētu veikt sql pieprasījumus.")
    global connection
    config_file.read('config.ini')
    databaseconfig = config_file["DATABASECONFIG"]
    connection = mysql.connector.connect(
        host=databaseconfig["host"], user=databaseconfig["user"], passwd=databaseconfig["passwd"])
    cursor = connection.cursor()
    cursor.execute("CREATE DATABASE IF NOT EXISTS {}".format(
        databaseconfig["database"]))

# izveido datubazi lietosanai
def init_db():
    logger.info("init_db() Izveido datu bāzi pēc config.ini datiem")
    config_file.read('config.ini')
    databaseconfig = config_file["DATABASECONFIG"]
    global connection
    connection = mysql.connector.connect(
        host="{}".format(databaseconfig["host"]),
        database="{}".format(databaseconfig["database"]),
        user="{}".format(databaseconfig["user"]),
        passwd="{}".format(databaseconfig["passwd"],
        autocommit = True)
    )

# iegust kursoru
def get_cursor():
    logger.info("get_cursor() Iegūst kursoru")
    global connection
    try:
        connection.ping(reconnect=True, attempts=1, delay=0)
        connection.commit()
        logger.info("Kursors iegūts.")
    except:
        logger.exception("Nav savienojuma ar datu bāzi.")
        connection = init_db()
        connection.commit()
    logger.info("get_cursor() beidz darbību.")
    return connection.cursor()

# veic sql pieprasijumus
def execute_cursor(query):
    try:
        logger.debug("Izpilda kursoru")
        cursor = get_cursor()
        logger.debug("Kursors mēģina izpildīt %s", query)
        cursor.execute(query)
    except:
        logger.exception('')
    logger.info("execute_cursor() beidz darbību")

# ievieto datus datubaze
def insert_into_db(query, values):
    try:
        logger.info("insert_into_db() Ievieto datus datubāzē")
        logger.debug("insert_into_db() sāk darbību.")
        cursor = get_cursor()
        cursor.execute(query, values)
    except:
        logger.exception('')
    logger.debug("insert_into_db() beidz darbību.")

# izdzes datus no datubazes
def remove_from_db(row_index):
    try:
        logger.info("remove_from__db() Izdzēš datus no datu bāzes")
        logger.debug("remove_from__db() sāk darbību.")
        cursor = get_cursor()
        query = "DELETE FROM usernms_n_passwds WHERE data_id = " + \
            str(row_index) + " AND row_owner = %s"
        cursor.execute(query, (masteruser,))
    except:
        logger.exception('')
    logger.debug("remove_from__db() beidz darbību.")

# izprinte datubazi (encrypted)
def view_db():
    try:
        logger.info("view_db() Izprintē datubāzes datus.")
        query = "SELECT data_id, site, usernm, passwd, comment FROM usernms_n_passwds WHERE row_owner = %s"
        cursor = get_cursor()
        cursor.execute(query, (masteruser,))
        for row in cursor:
            print(row)
    except:
        logger.exception('')
    logger.info("view_db() beidz darbību")

# izprinte datubazi (decrypted)
def view_decrypted_db():
    try:
        logger.info(
            "view_decrypted_db() Atšifrē datubāzes datus un izprintē tos")
        query = "SELECT data_id, site, usernm, passwd, comment FROM usernms_n_passwds WHERE row_owner = %s"
        cursor = get_cursor()
        cursor.execute(query, (masteruser,))
        for row in cursor:
            element_arr = []
            column_count = 0
            for element in row:
                if(column_count == 0):
                    element_arr.append(element)
                    column_count = column_count + 1
                else:
                    element_arr.append(do_decrypt(element))
            print(element_arr)
    except:
        logger.exception('')
    logger.info("view_decrypted_db() beidz darbību")

#atslēgas iegūšana
def gen_key():
    try:
        logger.info(
            "# gen_key() sāk darbību failā")
        global f_key
        logger.debug(
            "Generē Fernet atslēgu no ievades lauka masterpass")
        global masteruser
        masteruser = input('Ievadied lietotājvārdu:')
        masterpass = input('Ievadiet saimniekparoli:')
        masterpass_in_bytes = bytes(masterpass, 'utf-8')
        curr_salt = b"\xf4\x17\xed\xe7,\xeb\x13'\x8e\x1b7\xce\x12c\xc9\x8e"
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                         length=32, salt=curr_salt, iterations=39000)
        key = base64.urlsafe_b64encode(kdf.derive(masterpass_in_bytes))
        f_key = Fernet(key)
    except:
        logger.exception('')
    logger.info("gen_key() beidz darbību")

# sifre padotos datus
def do_encrypt(data_to_encrypt):
    try:
        logger.debug("Šifrē padotos datus")
        encrypted_data = f_key.encrypt(data_to_encrypt.encode())
        return encrypted_data
    except:
        logger.exception('')
    logger.info("do_encrypt() beidz darbību")

# atsifre padotos datus
def do_decrypt(data_to_decrypt):
    try:
        logger.debug("Atšifrē padotos datus")
        decrypted_data = f_key.decrypt(
            bytes(data_to_decrypt, encoding='utf8')).decode()
        return decrypted_data
    except:
        logger.exception('')
    logger.info("de_decrypt() beidz darbību")

#PROGRAMMAS CIKLS
init_config()
logger.info("Inicializē config.ini failu")
gen_key()
print("Logged in as ", masteruser)
logger.info("Atrod Fernet atslēgu")
connection = None
connected = False
init_db_template()
init_db()
logger.info("Inicializē datubāzi.")
try:
    logger.info("Izveido tabulu.")
    execute_cursor("CREATE TABLE IF NOT EXISTS usernms_n_passwds (data_id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, row_owner TEXT, site TEXT, usernm TEXT, passwd TEXT, comment TEXT)")
except:
    logger.exception('Nevarēja izveidot vajadzīgo tabulu')
user_action = 0
while (str(user_action) != "x"):
    user_action = input(
        "Choose an action: v = View data, m = Modify data, x = Exit program:")
    if(str(user_action) == "v"):
        while True:
            
            user_action = input("View encrypted or decrypted? e = encrypted, d = decrypted, xv = exit view option:")

            if(str(user_action) == "e"):
                view_db()
                break
            elif(str(user_action) == "d"):
                view_decrypted_db()
                break
            elif(str(user_action) == "xv"):
                print("Exiting view option.")
                break
            else:
                print("ILLEGAL INPUT")
                continue
        continue
    elif(str(user_action) == "m"):
        while (str(user_action) != "x"):
            user_action = input(
                "You have chosen to modify data. Do you wish to add or remove data? (+ = add, - = remove, xm = exit modify option):")
            if(str(user_action) == "+"):
                domain_input = input("Enter the domain:")
                user_email_input = input("Enter the username/email:")
                password_input = input("Enter the password:")
                comment_input = input("Enter a comment:")
                print("Your full input: ", domain_input, " ",
                      user_email_input, " ", password_input, " ", comment_input)
                while True:
                    user_action = input(
                        "Continue to storing in db? y = yes, n = no:")
                    if (str(user_action) == "y"):
                        encrypted_domain = do_encrypt(str(domain_input))
                        encrypted_user_email = do_encrypt(
                            str(user_email_input))
                        encrypted_password = do_encrypt(str(password_input))
                        encrypted_comment = do_encrypt(str(comment_input))
                        insert_into_db("INSERT INTO usernms_n_passwds (row_owner, site, usernm, passwd, comment) VALUES (%s,%s,%s,%s,%s)", (
                            masteruser, encrypted_domain, encrypted_user_email, encrypted_password, encrypted_comment))
                        connection.commit()
                        print("Database modified. Exiting.")
                        break
                    elif (str(user_action) == "n"):
                        print("Changes revoked. Exiting.")
                        break
                    else:
                        print("ILLEGAL INPUT")
                        continue
            elif(str(user_action) == "-"):
                while True:
                    view_decrypted_db()
                    selected_row = input("select a row to remove it:")
                    if(selected_row.isdigit()):
                        confirm_change = input(
                            "Remove item with id {}? y = yes, n = no:".format(int(selected_row)))
                        if(str(confirm_change) == "y"):
                            remove_from_db(selected_row)
                            connection.commit()
                            break
                        elif(str(confirm_change) == "n"):
                            break
                        else:
                            print("ILLEGAL INPUT")
                            continue
                    else:
                        print("ILLEGAL INPUT")
                        continue
            elif (str(user_action) == "xm"):
                print("Exiting modify option.")
                break

    elif(str(user_action) == "x"):
        print("Exiting program")
        break
    else:
        print("ILLEGAL INPUT")
        continue
logger.info("# Programma beidzas")