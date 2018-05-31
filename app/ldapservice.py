import ldap
import ldap.modlist
from user import User

class LdapService:
    con=None

    def __init__(self):
        self.connect_ldap()

    def connect_ldap(self):
        print "INITIALIZING LDAP SERVER ...."
        self.con = ldap.initialize('ldap://127.0.0.1')

        # At this point, we're connected as an anonymous user
        # If we want to be associated to an account
        # you can log by binding your account details to your connection

        self.con.simple_bind_s("cn=admin,dc=chat,dc=app", "chatapp")
        print "LDAP Server Listening...."

    def add_user(self,user):
        print "ADDING USER"
        dn = "uid="+user.name+",ou=Users,dc=chat,dc=app"
        modlist = {
            "objectClass": ["inetOrgPerson","person"],
            "uid": user.name,
            "sn": user.surname,
            "givenName": user.name,
            "cn": user.name+" "+user.surname,
            "displayName": user.name+" "+user.surname,
            "userPassword": user.password,
            "description": user.card_number,
            "mail":user.email

            }
        #USE "strongAuthenticationUser" objectClass for Certification, it needs a binary file,
        # addModList transforms your dictionary into a list that is conform to ldap input.
        result = self.con.add_s(dn, ldap.modlist.addModlist(modlist))
        print "User ADDED!"
        print "Result : "+str(result)
        self.con.unbind_s()

    def delete_user(self,uid):
        ########## deleting (a user) #################################################
        print "Deleting user "+uid
        dn = "uid="+uid+",ou=Users,dc=chat,dc=app"
        self.con.delete_s(dn)

    def search_user(self,uid):
        ldap_base = "ou=Users,dc=chat,dc=app"
        query = "(uid="+uid+")"
        try:
            result = self.con.search_s(ldap_base, ldap.SCOPE_SUBTREE, query)
            self.con.unbind_s()
            print "Connection closed!"
            if result==[]:
                print "User not found"
                return None
            else:
                uid = result[0][1]['uid']
                lastname = result[0][1]['sn']
                name = result[0][1]['givenName']
                password = result[0][1]['userPassword']
                card_number = result[0][1]['description']
                email = result[0][1]['mail']
                user = User(uid, name, lastname, email, password, card_number, "")
                return user
        except Exception as e:
            print "Error in SEARCH USER "+e
            return None


