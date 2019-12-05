import logging


# Todo 
# add functions to change pd display options on the fly

class database:

    def __init__(self, conn):
        self.conn = conn

    @staticmethod
    def db_schema(db_conn):
        db_conn.execute('''CREATE TABLE "computers" (
            "id" integer PRIMARY KEY,
            "ip" text,
            "hostname" text,
            "domain" text,
            "os" text,
            "dc" boolean
            )''')

        # type = hash, plaintext
        db_conn.execute('''CREATE TABLE "users" (
            "id" integer PRIMARY KEY,
            "assignedPlans" text,
            "displayName" text,
            "mail" text,
            "mailNickname" text,
            "objectId" text,
            "sid" text,
            "otherMails" text,
            "telephoneNumber" text,
            "userPrincipalName" text
            )''')

        db_conn.execute('''CREATE TABLE "groups" (
            "id" integer PRIMARY KEY,
            "domain" text,
            "name" text
            )''')

        db_conn.execute('''CREATE TABLE "apps" (
            "id" integer PRIMARY KEY,
            "DisplayName" text,
            "appId" text,
            "homepage" text,
            "objectId" text,
            "allowGuestsSignIn" text,
            "keyCredentials" text,
            "passwordCredentials" text,
            "wwwHomepage" text
            )''')

        db_conn.execute('''CREATE TABLE "vms" (
            "id" integer PRIMARY KEY,
            "userid" integer,
            "groupid" integer,
            FOREIGN KEY(userid) REFERENCES users(id),
            FOREIGN KEY(groupid) REFERENCES groups(id)
            )''')

        db_conn.execute('''CREATE TABLE "spns" (
            "id" integer PRIMARY KEY,
            "userid" integer,
            "groupid" integer,
            FOREIGN KEY(userid) REFERENCES users(id),
            FOREIGN KEY(groupid) REFERENCES groups(id)
            )''')


    def add_app(self, DisplayName, appId, homepage, objectId, allowGuestsSignIn, keyCredentials, passwordCredentials, wwwHomepage):
        """Check if this app has already been added to the database, if not add it in.
        """

        cur = self.conn.cursor()

        cur.execute('SELECT * FROM apps WHERE appId LIKE ?', [appId])
        results = cur.fetchall()

        if not len(results):
            cur.execute("INSERT INTO apps (DisplayName, appId, Homepage, objectId, allowGuestsSignIn, keyCredentials, passwordCredentials, wwwHomepage) VALUES (?,?,?,?,?,?,?,?)", [DisplayName, appId, homepage, objectId, allowGuestsSignIn, keyCredentials, passwordCredentials, wwwHomepage])

        cur.close()

        return cur.lastrowid


    def add_user(self, userObj):
        """Check if this user has already been added to the database, if not add them in.

        userObj is a json object containing all user info retrieved from azure
        """

        displayName = str(userObj['displayName'])
        mail = str(userObj['mail'])
        mailNickname = str(userObj['mailNickname'])
        objectId = str(userObj['objectId'])
        onPremisesSecurityIdentifier = str(userObj['onPremisesSecurityIdentifier'])
        otherMails = str(userObj['otherMails'])
        telephoneNumber = str(userObj['telephoneNumber'])
        userPrincipalName = str(userObj['userPrincipalName'])

        plans = []
        for plan in userObj["assignedPlans"]:
            plans.append(plan["service"])

        assignedPlans = str(plans)


        cur = self.conn.cursor()

        cur.execute('SELECT * FROM users WHERE objectId=?', [objectId])
        results = cur.fetchall()

        if not len(results):
            cur.execute("INSERT INTO users (assignedPlans, displayName, mail, mailNickname, objectId, sid, otherMails, telephoneNumber, userPrincipalName) VALUES (?,?,?,?,?,?,?,?,?)", [assignedPlans, displayName, mail, mailNickname, objectId, onPremisesSecurityIdentifier, otherMails, telephoneNumber, userPrincipalName])

        cur.close()

        return cur.lastrowid