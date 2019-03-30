using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.ServiceModel.Channels;
using System.Xml.XPath;
using System.IO;
using System.Xml;
using Microsoft.Web.Services2.Security;
using Microsoft.Web.Services2.Security.Tokens;
using System.Collections.Generic;
using System.Text;
using System.Net;
using Microsoft.Web.Services2.Security.Utility;

namespace Servicios.Clases
{
    /// <summary>
    /// Clase que se usa para firmar el Request xml.
    /// </summary>
    public class ProcessXmlRequest
    {

        /*Atención: 
         Los procedimientos aquí realizados son basados y cumplen con la especificación 
         OASIS Web Service Security 1.1
         (https://www.oasis-open.org/committees/download.php/16790/wss-v1.1-spec-os-SOAPMessageSecurity.pdf),
         La especificación XML Encryption Syntax and Processing(https://www.w3.org/TR/2002/REC-xmlenc-core-20021210/Overview.html)
         y la Espeficación XML Signature Syntax and Processing(https://www.w3.org/TR/xmldsig-core1/)
         No cambiar nada de lo que hay acá, inclusive el orden de los elementos puede causar errores fatales en 
         el servidor al querer procesar el mensaje.
         Si se quiere cambiar algo, por favor, guiarse y adherirse a la especificación de OASIS Web Service Security 1.1
             */

        public static Message GetSignedRequest(ref Message unsignedRequest)
        {

            #region Obtener el XML del Message

            MessageBuffer messageBuffer = unsignedRequest.CreateBufferedCopy(Int32.MaxValue); //Crea una copia de request en el Buffer de tamaño Int32.MaxValue

            XPathNavigator xpathNavigator = messageBuffer.CreateNavigator(); //Creamos un Cursor para navegar a través del mensaje xml (messageBuffer)

            

            //Cargar el mensaje en un documento xml.
            MemoryStream memoryStream = new MemoryStream();
            XmlWriter escritorXml= XmlWriter.Create(memoryStream);

            xpathNavigator.WriteSubtree(escritorXml);
            escritorXml.Flush();
            escritorXml.Close();
            memoryStream.Position = 0;

            //Creamos un documento XML vacio 
            XmlDocument xmldoc = new XmlDocument()
            {
                PreserveWhitespace = true
            };
            xmldoc.Load(XmlReader.Create(memoryStream));
            #endregion

            PrepararXml(ref xmldoc);


            //Obtenemos los certificados requeridos para Firmas y Encriptar.
            //Aquí comienza la magia.

            X509Certificate2 certificadoconllaveprivada = RetrieveCertificate(true, "cf0b691745fd90204f387214e49ffc3e7b48f3c0");
            X509Certificate2 certificadopublico = RetrieveCertificate(false, "3febb2423e8baf23ae4ee30672551e766f0a536b");
            #region Obtener el XML firmado y encriptado y lo convierte en un objeto Message



            XmlDocument newxml = FirmaryEncriptarSoapRequest(xmldoc, certificadoconllaveprivada, certificadopublico);
            newxml.PreserveWhitespace = true;
            escritorXml = XmlWriter.Create(memoryStream);
            memoryStream.Position = 0;
            newxml.Save(escritorXml);
            escritorXml.Flush();
            escritorXml.Close();
            memoryStream.Position = 0;

            XmlDictionaryReader xdr = XmlDictionaryReader.CreateTextReader(memoryStream, new XmlDictionaryReaderQuotas());
            Message newMessage = Message.CreateMessage(xdr, Int32.MaxValue, unsignedRequest.Version);
            newMessage.Properties.CopyProperties(unsignedRequest.Properties);
            #endregion 
            return newMessage;

        }

        private static void PrepararXml(ref XmlDocument xmldoc)
        {
            //aquí se hace una preparación previa del xml para que tanto la firma como 
            //la encriptación se realice correctamente.

            XmlNamespaceManager namespaceManager = new XmlNamespaceManager(xmldoc.NameTable);
            namespaceManager.AddNamespace("s", "http://schemas.xmlsoap.org/soap/envelope/");
            namespaceManager.AddNamespace("soapenv", "http://schemas.xmlsoap.org/soap/envelope/");
            if (xmldoc.FirstChild is XmlDeclaration)
            {
                xmldoc.RemoveChild(xmldoc.FirstChild);
            }

            //Seleccionar el Envelope.
            XmlElement envelopeNode = xmldoc.DocumentElement.SelectSingleNode("//s:Envelope", namespaceManager) as XmlElement;
            envelopeNode.SetAttribute("xmlns:lib", "http://libertytypes.com.iaxis.services");
            envelopeNode.Prefix = "soapenv";
            envelopeNode.RemoveAttribute("xmlns:s");

            foreach (XmlNode childNode in envelopeNode.ChildNodes)
            {
                childNode.Prefix = "soapenv";
            }

            //Seleccionar el body
            XmlElement quotationCarGenericRq = xmldoc.GetElementsByTagName("quotationCarGenericRq")[0] as XmlElement;
            quotationCarGenericRq.RemoveAllAttributes();
            foreach (XmlNode childNode in quotationCarGenericRq.ChildNodes)
            {
                ((XmlElement)childNode).RemoveAllAttributes();
            }
            quotationCarGenericRq.Prefix = "lib";


            //Seleccionar el header

            XmlElement header = xmldoc.DocumentElement.SelectSingleNode("//soapenv:Header", namespaceManager) as XmlElement;
            //Seleccionar el Action y quitarlo.
            XmlElement action = xmldoc.GetElementsByTagName("Action")[0] as XmlElement;

            header.RemoveChild(action);

        }

        /// <summary>
        /// Firmar y Encriptar el Documento XML usando un Certificado x509.
        /// </summary>
        /// <param name="xmldoc">el documento XML a firmar y encriptar.</param>
        /// <param name="certificado">el certificado para poder firmar el XML</param>
        /// <param name="certificadopublico">el certificado publico para poder encriptar</param>
        /// <returns></returns>
        private static XmlDocument FirmaryEncriptarSoapRequest(XmlDocument xmldoc, X509Certificate2 certificadoPrivado, X509Certificate2 certificadopublico)
        {

            #region Firmar
            //añadir las referencias de espacios de nombres para asegurarnos de que podamos trabajar contra
            //cualquier documento elemento XML sin importar el nombramiento de los Tags siempre y cuando sepamos sus Namespaces.
            XmlNamespaceManager namespaceManager = new XmlNamespaceManager(xmldoc.NameTable);
            namespaceManager.AddNamespace("wsse", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
            namespaceManager.AddNamespace("wsu", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd");
            namespaceManager.AddNamespace("soapenv", "http://schemas.xmlsoap.org/soap/envelope/");

            //Seleccionar el Header para agregarle elementos.
            XmlElement headerNode = xmldoc.DocumentElement.SelectSingleNode("//soapenv:Header", namespaceManager) as XmlElement;
            //Creamos el nodo de seguridad <Security>
            XmlElement securityNode = xmldoc.CreateElement("wsse", "Security", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
            securityNode.SetAttribute("xmlns:wsu", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd");
            securityNode.SetAttribute("mustUnderstand", "http://schemas.xmlsoap.org/soap/envelope/", "1");
            XmlAttribute mustUnderstandSecurityAttribute = securityNode.GetAttributeNode("mustUnderstand");
            mustUnderstandSecurityAttribute.Prefix = "soapenv";



            #region Preparar elementos a ser firmados


            //Ahora vamos a crear otro BinarySecurityToken

            //Ahora creamos un BinarySecurityToken que será el certificado x509 de la clave privada
            //Con este BinarySecurityToken se espera que el receptor pueda verificar el Digest de la firma que se
            //genera con este BinarySecurityToken.
            //este BinarySecurityToken es firmado también.

            XmlElement binarySecurityTokenNode2 = xmldoc.CreateElement("wsse", "BinarySecurityToken", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
            //El atributo EncodingType dice cómo el Token está codificado, en este caso, Base64Binary.
            binarySecurityTokenNode2.SetAttribute("EncodingType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary");
            //El atributo ValueType indica qué es el BinarySecurityToken, en este caso un Certificado X509v3.
            binarySecurityTokenNode2.SetAttribute("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3");

            binarySecurityTokenNode2.SetAttribute("Id", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", XmlElementsIds.PrivateKeyBinarySecurityTokenUri);
            XmlAttribute attribute2 = binarySecurityTokenNode2.GetAttributeNode("Id");
            attribute2.Prefix = "wsu";
            binarySecurityTokenNode2.InnerText = Convert.ToBase64String(certificadoPrivado.GetRawCertData());

            //Creamos una estampa de tiempo, la cuál será firmada también:

            Timestamp timestamp = new Timestamp();
            timestamp.TtlInSeconds = 5000;

            //El body también será firmado, pero todavía no tiene los atributos requeridos para que pueda ser firmado
            //Aquí se los agrego.

            //Ahora vamos a ponerle un Id.
            XmlElement body = xmldoc.DocumentElement.SelectSingleNode("//soapenv:Body", namespaceManager) as XmlElement;
            body.SetAttribute("xmlns:wsu", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd");
            body.SetAttribute("Id", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", XmlElementsIds.BodyId);
            var bodyId = body.GetAttributeNode("Id");
            bodyId.Prefix = "wsu";

            #endregion

            #region Agregar elementos a ser firmados al nodo Security



            securityNode.AppendChild(timestamp.GetXml(xmldoc));
            securityNode.AppendChild(binarySecurityTokenNode2);
            //agregar
            headerNode.AppendChild(securityNode);
            //el body ya existe, y no pertenece al nodo security.

            #endregion

            //Al momento de computar la firma, la clase SignedXml buscará las referencias previamente puestas, (las busca por los Id de cada uno
            //de los elementos a ser firmados.
            //y firmará los elementos que las referencias han referenciado
            //valga la redundancia.

            #region Crear firma XML


            //Ahora vamos a agregar un elemento Signature, que representa la firma digital.

            SignedXml signedXml = new SignedXmlWithId(xmldoc);

            signedXml.Signature.Id = "SIG-3";
            //la canonicalización indica como se deben interpretar los espacios en blanco y similares
            //porque el valor de firma puede cambiar inclusive cuando hayan espacios u otros caracteres-
            signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
            //cual fue el algoritmo usado para firmar.
            signedXml.SignedInfo.SignatureMethod = SignedXml.XmlDsigRSASHA1Url;

            //Cada una de las referencias apunta a un Id, que deberán tener los elementos
            //a ser firmados.


            System.Security.Cryptography.Xml.Reference reference = new System.Security.Cryptography.Xml.Reference
            {
                Uri = "#" + XmlElementsIds.PrivateKeyBinarySecurityTokenUri
            };
            reference.AddTransform(new XmlDsigExcC14NTransform(""));
            reference.DigestMethod = SignedXml.XmlDsigSHA1Url;

            System.Security.Cryptography.Xml.Reference reference2 = new System.Security.Cryptography.Xml.Reference
            {
                Uri = "#" + timestamp.Id
            };
            reference2.AddTransform(new XmlDsigExcC14NTransform("wsse lib soapenv"));
            reference2.DigestMethod = SignedXml.XmlDsigSHA1Url;

            System.Security.Cryptography.Xml.Reference reference3 = new System.Security.Cryptography.Xml.Reference
            {
                Uri = "#" + XmlElementsIds.BodyId
            };
            reference3.AddTransform(new XmlDsigExcC14NTransform("lib"));
            reference3.DigestMethod = SignedXml.XmlDsigSHA1Url;


            signedXml.SignedInfo.AddReference(reference);
            signedXml.SignedInfo.AddReference(reference2);
            signedXml.SignedInfo.AddReference(reference3);
            signedXml.SigningKey = certificadoPrivado.PrivateKey; //la clave privada para firmar.

            //La Keyinfo representa un identificador de un Token de seguridad.
            //en el caso de las firmas, identifica cómo encontrar el token que se usó para firmar.
            KeyInfo keyInfoInsideSignature = new KeyInfo();
            keyInfoInsideSignature.Id = "KI-D313N3M1G0";

            //en este caso Una referencia a un token de seguridad.
            SecurityTokenReference securityTokenReferenceInsideSignature = new SecurityTokenReference();
            securityTokenReferenceInsideSignature.Id = "STR-SecurityTokenReference";
            securityTokenReferenceInsideSignature.ValueType = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3";
            securityTokenReferenceInsideSignature.Reference = XmlElementsIds.PrivateKeyBinarySecurityTokenUri; //El BinarySecurityToken que contiene el Certificado x509v3 usado para la firma (usando su clave privada)
            KeyInfoClause keyInfoClauseInsideSignature = new KeyInfoNode(securityTokenReferenceInsideSignature.GetXml());
            keyInfoInsideSignature.AddClause(keyInfoClauseInsideSignature);

            signedXml.KeyInfo = keyInfoInsideSignature;


            signedXml.ComputeSignature();

            //revisar que la firma sea válida.(para propósitos de desarrollo)
            bool firstcheck = signedXml.CheckSignature(certificadoPrivado, true);
            XmlNode signatureNode= signedXml.GetXml(); //Finalmente ya obtenemos un elemento <signature> totalmente formado y listo para ser anexado al nodo <security>
            #endregion


            securityNode.AppendChild(signatureNode);

 

            #endregion

            #region Encriptar

            //Ahora vamos a obtener el certificado público, y usar su clave para encriptar el contenido del body

            Encriptar(ref xmldoc, "lib:quotationCarGenericRq", certificadopublico, ref securityNode);

            #endregion

            //Devolver un XML Firmado y Encriptado.
            #region testing, se puede dejar comentado:
            //HttpWebRequest req = (HttpWebRequest)WebRequest.Create("https://wsqa.libertycolombia.com.co:8443/soa-infra/services/GenericAuto/GenericAutoQuotation/GenericAutoQuotationMediator_ep");
            //req.Headers.Add("SOAPAction", "urn:quotationCarGeneric");
            //req.Method = "POST";
            //req.UserAgent = "Apache-HttpClient/4.1.1 (java 1.5)";
            //req.ContentType = "text/xml;charset=\"utf-8\"";
            //req.Host = "wsqa.libertycolombia.com.co:8443";

            ////XmlDocument xmldoctest = new XmlDocument();
            ////xmldoctest.Load(@"C:\Users\CarlosAlbertoFiguere\Desktop\test.xml");

            //using (Stream stream = req.GetRequestStream())
            //{
            //    using (StreamWriter streamWriter = new StreamWriter(stream))
            //    {
            //        streamWriter.Write(xmldoc.OuterXml);

            //    }

            //}
            //try
            //{
            //    WebResponse lol = req.GetResponse();
            //    string response = (new StreamReader(lol.GetResponseStream())).ReadToEnd();

            //}
            //catch (WebException wex)
            //{
            //    string response = (new StreamReader(wex.Response.GetResponseStream())).ReadToEnd();
            //}
            #endregion

            return xmldoc;

        }

        

        /// <summary>
        /// Retrieves a certificate from the Personal Certificate Store in Windows.
        /// </summary>
        /// <param name="sujetoCertificado"></param>
        /// <returns></returns>
        static void Encriptar(ref XmlDocument document, string elementoParaEncriptar, X509Certificate2 certificadopublico, ref XmlElement securityNode)
        {

            RSACryptoServiceProvider rsaAlgorithm = (RSACryptoServiceProvider)certificadopublico.PublicKey.Key; //llave publica usada para encriptar.


            //Ahora creamos un BinarySecurityToken que será el certificado x509 de la clave pública 
            //se usa para que el receptor sepa qué certificado se usó para encriptar.
            XmlElement binarySecurityTokenNode = document.CreateElement("wsse", "BinarySecurityToken", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
            //El atributo EncodingType dice cómo el Token está codificado, en este caso, Base64Binary.
            binarySecurityTokenNode.SetAttribute("EncodingType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary");
            //El atributo ValueType indica qué es el BinarySecurityToken, en este caso un Certificado X509v3.
            binarySecurityTokenNode.SetAttribute("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3");

            binarySecurityTokenNode.SetAttribute("Id", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", XmlElementsIds.PublicKeyBinarySecurityTokenUri);
            XmlAttribute attribute = binarySecurityTokenNode.GetAttributeNode("Id");
            attribute.Prefix = "wsu";
            binarySecurityTokenNode.InnerText = Convert.ToBase64String(certificadopublico.GetRawCertData());


            //Creamos una llave simétrica la cuál servirá para codificar la información. //AES-128-CBC
            AesManaged algoritmosimetrico = new AesManaged()
            {
                Padding = PaddingMode.ISO10126,
                KeySize = 128,
                Mode = CipherMode.CBC,
            };

            System.Security.Cryptography.Xml.EncryptedKey encryptedKey = new System.Security.Cryptography.Xml.EncryptedKey();
            encryptedKey.EncryptionMethod = new System.Security.Cryptography.Xml.EncryptionMethod(EncryptedXml.XmlEncRSAOAEPUrl);
            encryptedKey.AddReference(new DataReference("#ED-31"));
            SecurityTokenReference securityTokenReference = new SecurityTokenReference();
            securityTokenReference.Reference = XmlElementsIds.PublicKeyBinarySecurityTokenUri;
            securityTokenReference.ValueType = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3";
            KeyInfo ekkeyInfo = new KeyInfo();
            ekkeyInfo.AddClause(new KeyInfoNode(securityTokenReference.GetXml()));
            encryptedKey.KeyInfo = ekkeyInfo;
            encryptedKey.CipherData = new CipherData(EncryptedXml.EncryptKey(algoritmosimetrico.Key, rsaAlgorithm, true));



            securityNode.PrependChild(document.ImportNode(encryptedKey.GetXml(), true));
            securityNode.PrependChild(binarySecurityTokenNode);



            //Crear un XmlElement a través del nombre del Tag que se encuentra en el documento Xml especificado.
            XmlElement elementoParaEncriptarXML = document.GetElementsByTagName(elementoParaEncriptar)[0] as XmlElement;

           

            //Creamos una instancia de la clase EncryptedXml y usarla para encriptar
            //el XmlElement: elementoParaEncriptarXML; usando la llave simétrica que acabamos de
            //crear.
            EncryptedXml xmlEncriptado = new EncryptedXml();

            //Encriptamos el Body (elementoParaEncriptarXML) usando el algoritmo simétrico AES-128-CBC y lo dejamos ahí.
            byte[] elementoEncriptado = xmlEncriptado.EncryptData(elementoParaEncriptarXML, algoritmosimetrico, false);


            //Ahora creamos una instancia de la clase EncryptedData que representa
            //un elemento <EncryptedData> en el documento XML.
            System.Security.Cryptography.Xml.EncryptedData encryptedData = new System.Security.Cryptography.Xml.EncryptedData()
            {
                Type = EncryptedXml.XmlEncElementContentUrl,
                Id = "ED-31", 

                //Le asignamos otra propiedad a este elemento <EncryptedData> que es un EncryptionMethod
                //para que el receptor sepa que algoritmo usar para descifrar
                EncryptionMethod = new System.Security.Cryptography.Xml.EncryptionMethod(EncryptedXml.XmlEncAES128Url) //Aes-128-cbc o Rjindael.
            };
            encryptedData.CipherData = new CipherData(elementoEncriptado);

            /* Para descencriptar: Funciona, es para testear si puedo desencriptar los datos.
            var lmao= xmlEncriptado.DecryptData(encryptedData, algoritmosimetrico);
            var decrypted = Encoding.UTF8.GetString(lmao);
            */

            //Reemplazamos el elemento quotationCarGenericRq sin encriptar del documento XML con el elemento <EncryptedData> (que contiene el Body y sus contenidos encriptados) básicamente.
            //totalmente lleno.
            EncryptedXml.ReplaceElement(elementoParaEncriptarXML, encryptedData, false);


        }
        public static X509Certificate2 RetrieveCertificate(bool isPrivate, string certificateThumbprint)
        {

            X509Certificate2 certificado = new X509Certificate2();
            try
            {
                // Open the store of personal certificates.
                X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
                store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

                var collectionfound = store.Certificates.Find(X509FindType.FindByThumbprint, certificateThumbprint, false);

                /*
                X509Certificate2Collection collection = (X509Certificate2Collection)store.Certificates;
                X509Certificate2Collection fcollection = (X509Certificate2Collection)collection.Find(X509FindType.FindByTimeValid, DateTime.Now, false);
                X509Certificate2Collection scollection = X509Certificate2UI.SelectFromCollection(fcollection, "Sign", "Select certificate", X509SelectionFlag.SingleSelection);
                */



                if (collectionfound != null && collectionfound.Count > 0)
                {
                    certificado = collectionfound[0];

                    if (isPrivate == true && certificado.HasPrivateKey == false)
                    {
                        throw new Exception("A certificate was found, but, it does not have private key");
                    }
                }
                else
                {
                    throw new Exception("No certificates found with this thumbprint");
                }

                store.Close();
            }
            catch
            {
                throw;
            }

            return certificado;
        }


    }
    public class XmlElementsIds
    {
        public const string PublicKeyBinarySecurityTokenUri = "PublicKeyUri";
        public const string PrivateKeyBinarySecurityTokenUri = "PrivateKeyUri";
        public const string EncryptedKeyId = "EK-M1NMBR332C4RL02C";
        public const string BodyId = "BODYID";

    }
}