import base64
import hashlib
import subprocess
import tempfile
from datetime import datetime, timedelta

import requests
from OpenSSL import crypto
from lxml import etree
from odoo.exceptions import ValidationError

import logging
_logger = logging.getLogger(__name__)


def get_element(element_root, xpath, namespace):
    #if update:
    #    namespace.update({'des': 'http://DescargaMasivaTerceros.sat.gob.mx'})
    if 'ag' in namespace:
        namespace.update({'des': 'http://DescargaMasivaTerceros.sat.gob.mx'})
        _logger.error("get_element namespace????????????????????????????????:  {} ".format(namespace))
    element = element_root.find(xpath, namespace)
    if element is None:
        _logger.error("get_element errororororor: {} dos {} y tres {} ".format(element_root,xpath,namespace))
        raise ValidationError(f"{xpath} \n get_element_Element is not located in XML.")
    else:
        _logger.info("get_elementg suscces succes succes {}".format(element))
        return element


def set_element(element, data):
    if element is None:
        raise ValidationError("Element is not there to set text.")
    else:
        element.text = data


class SAT:
    DATE_TIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'
    external_nsmap = None

    def __init__(self, signature, key, password):
        self.certificate = crypto.load_certificate(crypto.FILETYPE_ASN1, base64.b64decode(signature))
        self.holder_vat = self.certificate.get_subject().x500UniqueIdentifier.split(' ')[0]
        self.key_pem = self.convert_key_cer_to_pem(base64.decodebytes(key), password.encode('UTF-8'))
        self.private_key = crypto.load_privatekey(crypto.FILETYPE_PEM, self.key_pem)

    # This function is in odoo already
    def convert_key_cer_to_pem(self, key, password, *args):
        # TODO compute it from a python way
        with tempfile.NamedTemporaryFile('wb', suffix='.key', prefix='edi.mx.tmp.') as key_file, \
                tempfile.NamedTemporaryFile('wb', suffix='.txt', prefix='edi.mx.tmp.') as pwd_file, \
                tempfile.NamedTemporaryFile('rb', suffix='.key', prefix='edi.mx.tmp.') as keypem_file:
            key_file.write(key)
            key_file.flush()
            pwd_file.write(password)
            pwd_file.flush()
            subprocess.call(('openssl pkcs8 -in %s -inform der -outform pem -out %s -passin file:%s' % (
                key_file.name, keypem_file.name, pwd_file.name)).split())
            key_pem = keypem_file.read()
        return key_pem

    def check_response(self, response: requests.Response, result_xpath, external_nsmap,token=False):
        try:
            response_xml = etree.fromstring(
                response.text,
                parser=etree.XMLParser(huge_tree=True)
            )
        except Exception:
            raise Exception(response.text)
        _logger.info("aaaaaaaaaaaa {}  y el otro es {}".format(response.status_code,response.text))
        if str(response.status_code) != str(requests.codes['ok']):
            _logger.info("iiiiiiiiiiii {}  y el otro es {}".format(response.status_code,requests.codes['ok']))
            error = get_element(response_xml, 's:Body/s:Fault/faultstring', external_nsmap)
            fault_string = response_xml.xpath('//s:Fault/faultstring/text()', namespaces=external_nsmap)
            _logger.error("SOAP Fault: %s", fault_string)
            raise Exception("0erererer.."+str(error))
        #_logger.info("xxaxaxaxaxaxaxax",response_xml)
        _logger.error("get_element: {} dos {} y tres {} ".format(response_xml,result_xpath,external_nsmap))
        if token == True:
            external_nsmap.update({'': 'http://DescargaMasivaTerceros.gob.mx'})
        return get_element(response_xml, result_xpath, external_nsmap)

    def get_headers(self, soap_action, token=False):
       headers = {
           'Content-type': 'text/xml;charset="utf-8"',
           'Accept': 'text/xml',
           'Cache-Control': 'no-cache',
           'SOAPAction': soap_action,
           'Authorization': 'WRAP access_token="{}"'.format(token) if token else ''
       }
       return headers

    # def get_headers(self, soap_action, token=False):
    #     headers = {
    #         'Content-Type': 'text/xml; charset=utf-8',
    #         'SOAPAction': f'{soap_action}',  # Entre comillas
    #     }
    #     if token:
    #         headers['Authorization'] = f'WRAP access_token="{token}"'
    #     return headers

    def sign(self, esignature_cer_bin, solicitud):
        internal_nsmap = {
            '': 'http://www.w3.org/2000/09/xmldsig#',
            's': 'http://schemas.xmlsoap.org/soap/envelope/',
            'u': 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd',
            'o': 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd',
            'des': 'http://DescargaMasivaTerceros.sat.gob.mx',
        }

        body = '<Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod ' \
               'Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod ' \
               'Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><Reference><Transforms><Transform ' \
               'Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></Transforms><DigestMethod ' \
               'Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><DigestValue></DigestValue></Reference' \
               '></SignedInfo><SignatureValue></SignatureValue><KeyInfo><X509Data><X509IssuerSerial' \
               '><X509IssuerName></X509IssuerName><X509SerialNumber></X509SerialNumber></X509IssuerSerial' \
               '><X509Certificate></X509Certificate></X509Data></KeyInfo></Signature> '
        parser = etree.XMLParser(remove_blank_text=True)
        element_root = etree.fromstring(body, parser)

        element_digest = hashlib.sha1(etree.tostring(solicitud.getparent(), method='c14n', exclusive=1)).digest()
        element = get_element(element_root, 'SignedInfo/Reference/DigestValue', internal_nsmap)
        set_element(element, base64.b64encode(element_digest))

        element_to_sign = get_element(element_root, 'SignedInfo', internal_nsmap)
        element_to_sign = etree.tostring(element_to_sign, method='c14n', exclusive=1)
        signed_info = base64.b64encode(crypto.sign(self.private_key, element_to_sign, 'sha1')).decode("UTF-8").replace(
            "\n", "")
        element = get_element(element_root, 'SignatureValue', internal_nsmap)
        set_element(element, signed_info)

        element = get_element(element_root, 'KeyInfo/X509Data/X509Certificate', internal_nsmap)
        set_element(element, esignature_cer_bin)

        d = self.certificate.get_issuer().get_components()
        cer_issuer = u','.join(['{key}={value}'.format(key=key.decode(), value=value.decode()) for key, value in d])
        element = get_element(element_root, 'KeyInfo/X509Data/X509IssuerSerial/X509IssuerName', internal_nsmap)
        set_element(element, cer_issuer)

        serial = str(self.certificate.get_serial_number())
        element = get_element(element_root, 'KeyInfo/X509Data/X509IssuerSerial/X509SerialNumber', internal_nsmap)
        set_element(element, serial)

        solicitud.append(element_root)
        return solicitud

    def prepare_soap_download_data(self, esignature_cer_bin, arguments, body, xpath):
        internal_nsmap = {
            '': 'http://www.w3.org/2000/09/xmldsig#',
            's': 'http://schemas.xmlsoap.org/soap/envelope/',
            'u': 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd',
            'o': 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd',
            'des': 'http://DescargaMasivaTerceros.gob.mx',
            'ag':True
        }
        element_root = etree.fromstring(body)
        #internal_nsmap['des'] = 'http://DescargaMasivaTerceros.sat.gob.mx'
        _logger.error("prepare_soap_download_data:  param1 {} param2 {} y param3 {} ".format(body,xpath,internal_nsmap))

        solicitud = get_element(element_root, xpath, internal_nsmap)
        try:
            for key in arguments:
                if key == 'RfcReceptores':
                    for i, rfc_receptor in enumerate(arguments[key]):
                        if i == 0:
                            xpath = 's:Body/des:SolicitaDescargaRecibidos/des:solicitud'
                            element = get_element(element_root, xpath, internal_nsmap)
                            set_element(element, rfc_receptor)
                    continue
                if arguments[key] != None:
                    solicitud.set(key, arguments[key])
            self.sign(esignature_cer_bin, solicitud)
        except Exception as e:
            raise ValidationError(f"Check SAT Credentials.\n {e}. \n {arguments}")
        return etree.tostring(element_root, method='c14n', exclusive=1)

    def soap_generate_token(self, certificate: crypto.X509, private_key: crypto.PKey):
        soap_url = 'https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/Autenticacion/Autenticacion.svc'
        soap_action = 'http://DescargaMasivaTerceros.gob.mx/IAutenticacion/Autentica'
        result_xpath = 's:Body/AutenticaResponse/AutenticaResult'
        #result_xpath = 's:Body/t:AutenticaResponse/t:AutenticaResult'


        internal_nsmap = {
            '': 'http://www.w3.org/2000/09/xmldsig#',
            's': 'http://schemas.xmlsoap.org/soap/envelope/',
            'u': 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd',
            'o': 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd',
            'des': 'http://DescargaMasivaTerceros.sat.gob.mx',  # 👈 aquí sin ".sat"
        }
        external_nsmap = {
            '': 'http://DescargaMasivaTerceros.sat.gob.mx',
            's': 'http://schemas.xmlsoap.org/soap/envelope/',
            'u': 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd',
            'o': 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd',
            #'t': 'http://DescargaMasivaTerceros.gob.mx',
        }

        date_created = datetime.utcnow()
        date_expires = date_created + timedelta(seconds=300)
        date_created = date_created.isoformat()
        date_expires = date_expires.isoformat()
        arguments = {'created': date_created, 'expires': date_expires}

        body = (
            '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
            'xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" '
            'xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">'
            '<s:Header><o:Security s:mustUnderstand="1">'
            '<u:Timestamp u:Id="Timestamp">'
            '<u:Created>{created}</u:Created>'
            '<u:Expires>{expires}</u:Expires>'
            '</u:Timestamp>'
            '<o:BinarySecurityToken u:Id="BinarySecurityToken" '
            'ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3" '
            'EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">'
            '</o:BinarySecurityToken>'
            '<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">'
            '<SignedInfo>'
            '<CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
            '<SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>'
            '<Reference URI="#Timestamp">'
            '<Transforms><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></Transforms>'
            '<DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>'
            '<DigestValue></DigestValue>'
            '</Reference>'
            '</SignedInfo>'
            '<SignatureValue></SignatureValue>'
            '<KeyInfo><o:SecurityTokenReference>'
            '<o:Reference ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3" '
            'URI="#BinarySecurityToken"/>'
            '</o:SecurityTokenReference></KeyInfo>'
            '</Signature>'
            '</o:Security></s:Header>'
            '<s:Body><Autentica xmlns="http://DescargaMasivaTerceros.gob.mx"/></s:Body>'
            '</s:Envelope>'
        ).format(**arguments)

        parser = etree.XMLParser(remove_blank_text=True)
        element_root = etree.fromstring(body, parser)

        element = get_element(element_root, 's:Header/o:Security/o:BinarySecurityToken', internal_nsmap)
        set_element(element, base64.b64encode(crypto.dump_certificate(crypto.FILETYPE_ASN1, certificate)))

        element = get_element(element_root, 's:Header/o:Security/u:Timestamp', internal_nsmap)
        element_digest = hashlib.sha1(etree.tostring(element, method='c14n', exclusive=1)).digest()
        element = get_element(element_root, 's:Header/o:Security/Signature/SignedInfo/Reference/DigestValue', internal_nsmap)
        set_element(element, base64.b64encode(element_digest))

        element_to_sign = get_element(element_root, 's:Header/o:Security/Signature/SignedInfo', internal_nsmap)
        element_to_sign = etree.tostring(element_to_sign, method='c14n', exclusive=1)
        signed_info = base64.b64encode(crypto.sign(private_key, element_to_sign, 'sha1')).decode("UTF-8").replace("\n", "")
        element = get_element(element_root, 's:Header/o:Security/Signature/SignatureValue', internal_nsmap)
        set_element(element, signed_info)

        soap_request = etree.tostring(element_root, method='c14n', exclusive=1)

        #_logger.info("==== SOAP URL: %s", soap_url)
        #_logger.info("==== SOAPAction HEADER: %s", soap_action)
        #_logger.info("==== PRIMERAS 300 CHARS XML:\n%s", soap_request[:300])
        communication = requests.post(
            soap_url,
            soap_request,
            headers=self.get_headers(soap_action),
            verify=True,
            timeout=15,
        )
        #_logger.error("check_response:  param1 {} param2 {} y param3 {} ".format(communication,result_xpath,external_nsmap))
        token = self.check_response(communication, result_xpath, external_nsmap,token=True)
        self.token = token.text
        return token.text

    def soap_request_download(self, token, date_from=None, date_to=None, rfc_emisor=None, tipo_solicitud='CFDI',
                              tipo_comprobante=None, rfc_receptor=None,
                              estado_comprobante=None, rfc_a_cuenta_terceros=None, complemento=None, uuid=None):
        soap_url = 'https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/SolicitaDescargaService.svc'
        #soap_action = 'http://DescargaMasivaTerceros.sat.gob.mx/ISolicitaDescargaService/SolicitaDescarga'
        soap_action = 'http://DescargaMasivaTerceros.sat.gob.mx/ISolicitaDescargaService/SolicitaDescargaRecibidos'
        result_xpath = 's:Body/SolicitaDescargaRecibidosResponse/SolicitaDescargaRecibidosResult'
        external_nsmap = {
            '': 'http://DescargaMasivaTerceros.sat.gob.mx',
            'des': 'http://DescargaMasivaTerceros.gob.mx',  # Agrega este alias
            's': 'http://schemas.xmlsoap.org/soap/envelope/',
            'u': 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd',
            'o': 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd',
            'h': 'http://DescargaMasivaTerceros.gob.mx',
            'xsi': 'http://www.w3.org/2001/XMLSchema-instance',
            'xsd': 'http://www.w3.org/2001/XMLSchema',
        }
        arguments = {
            #'RfcSolicitante': self.holder_vat,
            'FechaFinal': date_to.isoformat(),
            'FechaInicial': date_from.isoformat(),
            'TipoSolicitud': tipo_solicitud,
            'TipoComprobante': tipo_comprobante,
            'EstadoComprobante': 'Vigente',#estado_comprobante,
            'RfcACuentaTerceros': rfc_a_cuenta_terceros,
            'Complemento': complemento,
            'UUID': uuid,
            'RfcReceptor':self.holder_vat,
        }
        #if rfc_emisor:
        #    arguments['RfcEmisor'] = self.holder_vat
        #if rfc_receptor:
        #    arguments['RfcReceptores'] = [self.holder_vat]
        #<des:RfcSolicitante></des:RfcSolicitante>
        body = '''<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" 
           xmlns:des="http://DescargaMasivaTerceros.sat.gob.mx" xmlns:xd="http://www.w3.org/2000/09/xmldsig#">
           <s:Header/>
           <s:Body>
             <des:SolicitaDescargaRecibidos>
               <des:solicitud>
               </des:solicitud>
             </des:SolicitaDescargaRecibidos>
           </s:Body>
         </s:Envelope>'''
        xpath = 's:Body/des:SolicitaDescargaRecibidos/des:solicitud'
        cer = base64.b64encode(crypto.dump_certificate(crypto.FILETYPE_ASN1, self.certificate))
        soap_request = self.prepare_soap_download_data(cer, arguments, body, xpath)
        
        # if isinstance(soap_request, bytes):
        #    soap_request = soap_request.decode("utf-8")
        # soap_request = soap_request.replace(
        #    "http://DescargaMasivaTerceros.sat.gob.mx",
        #    "http://DescargaMasivaTerceros.gob.mx"
        # )


        _logger.error("==== SOAP URL: %s", soap_url)
        _logger.error("==== SOAPAction HEADER: %s", soap_action)
        _logger.error("==== HEADERS:\n%s", self.get_headers(soap_action, token))
        _logger.error("==== XML FINAL A ENVIAR ====\n%s", soap_request.decode() if isinstance(soap_request, bytes) else soap_request)

        communication = requests.post(
            soap_url,
            soap_request,
            headers=self.get_headers(soap_action, token),
            verify=True,
            timeout=15,
        )
        
        _logger.error("11 soap_request_download.. check_response:{} param1 {} y param3 {} ".format(communication,soap_request,token))
        _logger.error("soap_request_download.. check_response:  param1 {} param2 {} y param3 {} ".format(communication.text,result_xpath,external_nsmap))
        element_response = self.check_response(communication, result_xpath, external_nsmap)
        ret_val = {
            'id_solicitud': element_response.get('IdSolicitud'),
            'cod_estatus': element_response.get('CodEstatus'),
            'mensaje': element_response.get('Mensaje')
        }
        _logger.error("soap_request_download.. ret_val:  id_solicitud {}  ".format(ret_val))
        return ret_val

    def soap_verify_package(self, signature_holder_vat, id_solicitud, token):
        soap_url = 'https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/VerificaSolicitudDescargaService.svc'
        soap_action = 'http://DescargaMasivaTerceros.sat.gob.mx/IVerificaSolicitudDescargaService/VerificaSolicitudDescarga'
        result_xpath = 's:Body/VerificaSolicitudDescargaResponse/VerificaSolicitudDescargaResult'
        external_nsmap = {
            '': 'http://DescargaMasivaTerceros.sat.gob.mx',
            's': 'http://schemas.xmlsoap.org/soap/envelope/',
            'u': 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd',
            'o': 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd',
            'h': 'http://DescargaMasivaTerceros.sat.gob.mx',
            'xsi': 'http://www.w3.org/2001/XMLSchema-instance',
            'xsd': 'http://www.w3.org/2001/XMLSchema',
        }

        arguments = {
            'RfcSolicitante': signature_holder_vat,
            'IdSolicitud': id_solicitud,
        }
        body = '<s:Envelope xmlns:des="http://DescargaMasivaTerceros.sat.gob.mx" ' \
               'xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Header/><s:Body><des:VerificaSolicitudDescarga>' \
               '<des:solicitud IdSolicitud="" RfcSolicitante=""/>' \
               '</des:VerificaSolicitudDescarga></s:Body></s:Envelope>'
        xpath = 's:Body/des:VerificaSolicitudDescarga/des:solicitud'
        cer = base64.b64encode(crypto.dump_certificate(crypto.FILETYPE_ASN1, self.certificate))
        soap_request = self.prepare_soap_download_data(cer, arguments, body, xpath)
        communication = requests.post(
            soap_url,
            soap_request,
            headers=self.get_headers(soap_action, token),
            verify=True,
            timeout=15,
        )
        element_response = self.check_response(communication, result_xpath, external_nsmap)
        ret_val = {
            'cod_estatus': element_response.get('CodEstatus'),
            'estado_solicitud': element_response.get('EstadoSolicitud'),
            'codigo_estado_solicitud': element_response.get('CodigoEstadoSolicitud'),
            'numero_cfdis': element_response.get('NumeroCFDIs'),
            'mensaje': element_response.get('Mensaje'),
            'paquetes': []
        }
        for id_paquete in element_response.iter('{{{}}}IdsPaquetes'.format(external_nsmap[''])):
            ret_val['paquetes'].append(id_paquete.text)
        return ret_val

    def soap_download_package(self, signature_holder_vat, id_paquete, token):
        soap_url = 'https://cfdidescargamasiva.clouda.sat.gob.mx/DescargaMasivaService.svc'
        soap_action = 'http://DescargaMasivaTerceros.sat.gob.mx/IDescargaMasivaTercerosService/Descargar'
        result_xpath = 's:Body/RespuestaDescargaMasivaTercerosSalida/Paquete'
        external_nsmap = {
            '': 'http://DescargaMasivaTerceros.sat.gob.mx',
            's': 'http://schemas.xmlsoap.org/soap/envelope/',
            'u': 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd',
            'o': 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd',
            'h': 'http://DescargaMasivaTerceros.sat.gob.mx',
            'xsi': 'http://www.w3.org/2001/XMLSchema-instance',
            'xsd': 'http://www.w3.org/2001/XMLSchema',
        }

        arguments = {
            'RfcSolicitante': signature_holder_vat,
            'IdPaquete': id_paquete,
        }
        body = '<s:Envelope xmlns:des="http://DescargaMasivaTerceros.sat.gob.mx" ' \
               'xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Header/>' \
               '<s:Body><des:PeticionDescargaMasivaTercerosEntrada><des:peticionDescarga IdPaquete="" ' \
               'RfcSolicitante=""/></des:PeticionDescargaMasivaTercerosEntrada></s:Body></s:Envelope>'
        xpath = 's:Body/des:PeticionDescargaMasivaTercerosEntrada/des:peticionDescarga'
        cer = base64.b64encode(crypto.dump_certificate(crypto.FILETYPE_ASN1, self.certificate))
        soap_request = self.prepare_soap_download_data(cer, arguments, body, xpath)
        communication = requests.post(
            soap_url,
            soap_request,
            headers=self.get_headers(soap_action, token),
            verify=True,
            timeout=15,
        )
        element_response = self.check_response(communication, result_xpath, external_nsmap)
        element = element_response.getparent().getparent().getparent()
        respuesta = get_element(element, 's:Header/h:respuesta', external_nsmap)
        ret_val = {
            'cod_estatus': respuesta.get('CodEstatus'),
            'mensaje': respuesta.get('Mensaje'),
            'paquete_b64': element_response.text,
        }
        return ret_val
