using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.ServiceModel.Channels;
using System.Text;
using System.Web;
using System.Xml;
using System.Xml.XPath;

namespace Servicios.Clases
{
    public class DecryptXmlResponse
    {
        internal static Message GetDecryptedResponse(ref Message reply)
        {
            #region Obtener el XML del Message

            MessageBuffer messageBuffer = reply.CreateBufferedCopy(Int32.MaxValue); //Crea una copia de request en el Buffer de tamaño Int32.MaxValue

            XPathNavigator xpathNavigator = messageBuffer.CreateNavigator(); //Creamos un Cursor para navegar a través del mensaje xml (messageBuffer)



            //Cargar el mensaje en un documento xml.
            MemoryStream memoryStream = new MemoryStream();
            XmlWriter escritorXml = XmlWriter.Create(memoryStream);

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



            #region Desencriptar la respuesta.

            X509Certificate2 certificadoconllaveprivada = RetrieveCertificate(true, "cf0b691745fd90204f387214e49ffc3e7b48f3c0");

            #endregion
            #region Crear un message a partir del XML desencriptado.

            XmlDocument newxml = Decrypt(xmldoc, certificadoconllaveprivada);
            newxml.PreserveWhitespace = true;
            escritorXml = XmlWriter.Create(memoryStream);
            memoryStream.Position = 0;
            newxml.Save(escritorXml);
            escritorXml.Flush();
            escritorXml.Close();
            memoryStream.Position = 0;

            XmlDictionaryReader xdr = XmlDictionaryReader.CreateTextReader(memoryStream, new XmlDictionaryReaderQuotas());
            Message newMessage = Message.CreateMessage(xdr, Int32.MaxValue, reply.Version);
            newMessage.Properties.CopyProperties(reply.Properties);
            #endregion
            return newMessage;

        }
        static XmlDocument Decrypt(XmlDocument xmldoc, X509Certificate2 certificadoPrivado)
        {

            //Vamos a buscar el elemento EncryptedKey de la respuesta,
            //este encrypted key contiene la llave simétrica usada para encriptar el contenido del body.
            XmlNamespaceManager namespaceManager = new XmlNamespaceManager(xmldoc.NameTable);
            namespaceManager.AddNamespace("xenc", "http://www.w3.org/2001/04/xmlenc# ");

            string cipherValueOfEncryptedKey = xmldoc.FirstChild.NextSibling.FirstChild.LastChild.FirstChild.NextSibling.InnerText;

            byte[] cipherByteData = Convert.FromBase64String(cipherValueOfEncryptedKey);
            AesManaged symmetricAlgorithm = new AesManaged();
            symmetricAlgorithm.Key= EncryptedXml.DecryptKey(cipherByteData, (RSACryptoServiceProvider)certificadoPrivado.PrivateKey , true);
            symmetricAlgorithm.CreateDecryptor();

            EncryptedData encryptedData = new EncryptedData();
            encryptedData.LoadXml(xmldoc.FirstChild.NextSibling.LastChild.FirstChild as XmlElement);

            EncryptedXml encryptedXml = new EncryptedXml();
            var decrypted = Encoding.UTF8.GetChars(encryptedXml.DecryptData(encryptedData, symmetricAlgorithm));
            var plaintext = new string(decrypted);

            //TODO: Aquí es cuando debemos descencriptar.
            return new XmlDocument();
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
}