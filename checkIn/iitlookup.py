from pysimplesoap.client import SoapClient,SoapFault
import base64
class IITLookup:

        def __init__(self, wsurl, user=None, pwd=None, idlength=6):
                self.idlength=idlength
                if(user or pwd):
                    bts = ('%s:%s' % (user, pwd)).encode('ascii')
                    auth = base64.b64encode(bts).replace(b'\n', b'')
                    head = {'Authorization': "Basic %s" % auth.decode('ascii')}
                    self.sclient=SoapClient(wsdl=wsurl, sessions=True, http_headers=head)
                else:
                    self.sclient=SoapClient(wsdl=wsurl)

        def nameByID(self,idnumber):
                try:
                    return self.sclient.PCSGetName(idNumber=idnumber)['PCSGetNameResult']
                except SoapFault:
                    return None

        def nameIDByCard(self,cardnum):
                lookupstr = str(cardnum).zfill(self.idlength)
                try:
                    ret = self.sclient.PCSGetbyCardNum(cardNumber=lookupstr)['PCSGetbyCardNumResult']
                except SoapFault:
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

        def inquiryByID(self,idnumber):
                try:
                    ret = self.sclient.PCSGetInquiry(idNumber=idnumber)['PCSGetInquiryResult']
                except SoapFault:
                    return None
                output = {}
                for x in ret:
                    x = x['InquiryRecord']
                    n_obj = {}
                    n_obj['blocked'] = x['blocked']
                    n_obj['limit'] = x['limit']
                    n_obj['balance'] = x['balance']
                    output[x['tender']] = n_obj
                return output

        def inquiryByCard(self,cardnum):
                idn = self.nameIDByCard(cardnum)
                if not idn:
                        return None
                return self.inquiryByID(idn['idnumber'])

