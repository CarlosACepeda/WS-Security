using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace Servicios.Clases
{
    public class SignedXmlWithId: SignedXml
    {

        public SignedXmlWithId(XmlDocument xml)
            : base(xml)
        {
        }

        public SignedXmlWithId(XmlElement xmlElement)
            : base(xmlElement)
        {
        }
        public override XmlElement GetIdElement(XmlDocument document, string idValue)
        {
            //Al momento de computar la firma debemos ayudar a esta clase a obtener los elementos a ser firmados,
            //aquí hacemos eso.
            XmlElement idElem=  base.GetIdElement(document, idValue);

            //custom:
            if (idElem == null)
            {
                XmlNamespaceManager nsManager = new XmlNamespaceManager(document.NameTable);
                nsManager.AddNamespace("wsu", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd");

                idElem = document.SelectSingleNode("//*[@wsu:Id=\"" + idValue + "\"]", nsManager) as XmlElement;

            }
            return idElem;

        }
        
    }
}