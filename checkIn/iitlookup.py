from requests import Session, auth
import zeep


class IITLookup:

        def __init__(self, wsurl, user=None, pwd=None, idlength=6):
                self.idlength=idlength
                if(user or pwd):
                    session = Session()
                    session.auth = auth.HTTPBasicAuth(user, pwd)
                    self.sclient=zeep.Client(wsdl=wsurl, transport=zeep.Transport(session=session))
                else:
                    self.sclient=zeep.Client(wsdl=wsurl)

        def getServices(self):
            for service in self.sclient.wsdl.services.values():
                print(service)
                for port in service.ports.values():
                    print(port)
                    try:
                        operations = port.binding._operations.values()
                        for operation in operations:
                            print(operation.name)
                            node = self.sclient.create_message(self.sclient.service, operation.name)
                            print(node)
                    except zeep.exceptions.Error as zeep_error:
                        print(zeep_error)
                        return None

        def nameByID(self, idnumber):
                try:
                    return self.sclient.service.PCSGetName(idNumber=idnumber)
                except zeep.exceptions.Error as zeep_error:
                    print(zeep_error)
                    return None

        def nameIDByCard(self,cardnum):
                lookupstr = str(cardnum).zfill(self.idlength)
                try:
                    ret = self.sclient.service.PCSGetbyCardNum(cardNumber=lookupstr)
                except zeep.exceptions.Error as zeep_error:
                    print(zeep_error)
                    return None
                if(ret == 'Not Found'):
                    return None
                ret = ret.split(',')
                output = {}
                output['last_name'] = ret[0]
                output['first_name'] = ret[1]
                output['middle_name'] = ret[2]
                output['idnumber'] = ret[3]
                return output
