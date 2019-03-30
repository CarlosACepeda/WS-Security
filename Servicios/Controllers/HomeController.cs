using Servicios.QuotationMilenioLiberty;
using Microsoft.Web.Services2;
using Microsoft.Web.Services2.Security.Tokens;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.Web;
using System.Web.Mvc;
using System.Xml.Serialization;
using Servicios.Clases;
using System.Xml;
using Servicios.Models;

namespace Servicios.Controllers
{
    public class HomeController : Controller
    {

        [HttpGet]
        public ActionResult Index()
        {
            //XmlEncrypt();

            /*Creamos instancia del cliente webservice para poder inicializar sus Operaciones o metodos.
            verifica el web.config validando el Endpoint, en el Tag system.serviceModel*/
            QuotationCarGenericPortTypeClient client = new QuotationCarGenericPortTypeClient();

            var interceptorDePeticion = new CustomInspectorBehavior();
            //client.ClientCredentials.ClientCertificate.SetCertificate(StoreLocation.CurrentUser, StoreName.My, X509FindType.FindByThumbprint, "cf0b691745fd90204f387214e49ffc3e7b48f3c0");
            //client.ClientCredentials.ServiceCertificate.SetDefaultCertificate(StoreLocation.CurrentUser, StoreName.My, X509FindType.FindByThumbprint, "3febb2423e8baf23ae4ee30672551e766f0a536b");


            client.Endpoint.EndpointBehaviors.Add(interceptorDePeticion);

            //instancia del request
            quotationCarGenericRequest request = RequestLiberty();

            //Son las variables de salida que necesita el método #quotationCarGeneric.

            ElementoCodificado elementoCodificado = new ElementoCodificado();
            Prima datosEconomicos = new Prima();
            PSU[] PSU = new PSU[0];

            var response = client.quotationCarGeneric(ref request.amparo, request.automovil, request.conductor, ref request.datosGestion, request.infoRequest, request.preguntaPoliza, request.preguntaRiesgo, request.preguntaTablaRiesgo, request.preguntaTablaPoliza, request.tomadorPersonaJuridica, request.tomadorPersonaNatural, request.usuario, out elementoCodificado, out datosEconomicos, out PSU);

            //XmlSerializer xmlSerializer = new XmlSerializer(typeof(QuotationCarGenericRq));
            //using (StringWriter textwriter = new StringWriter())
            //{
            //    xmlSerializer.Serialize(textwriter, new QuotationCarGenericRq());
            //    var lmao= textwriter.ToString();
            //}


            return View();
        }


        public quotationCarGenericRequest RequestLiberty()
        {
            QuotationCarGenericPortTypeClient client = new QuotationCarGenericPortTypeClient();
            quotationCarGenericRequest request = new quotationCarGenericRequest();
            PersonaNatural conductor = new PersonaNatural();
            Automovil automovil = new Automovil();
            DatosGestion datosGestion = new DatosGestion();
            InfoRequest infoRequest = new InfoRequest();


            Amparo amp = new Amparo();
            amp.codigo = "775";
            amp.capital = "1000000000";
            //agrega objeto a un array, sin recorrerlo.
            Amparo[] amparo = new Amparo[] { amp };
            //amparo[0].codigo = "775";
            //amparo[0].capital = "1000000000";
            request.amparo = amparo;

            automovil.datos = new Datos_type0();
            automovil.datos.codigoFasecolda = "08001155";
            automovil.datos.modeloAnyo = 2014;
            automovil.identificacion = new Identificacion_type0();
            automovil.identificacion.color = new ElementoCodificado();
            automovil.identificacion.color.codigo = "4";
            automovil.identificacion.kilometraje = 0;
            automovil.identificacion.placa = new Placa();
            automovil.identificacion.placa.placa = "XXX111";
            automovil.identificacion.placa.tipoPlaca = new ElementoCodificado();
            automovil.identificacion.placa.tipoPlaca.codigo = "12";
            automovil.identificacion.valor = 30200000;
            automovil.identificacion.transportaCombustible = false;
            automovil.identificacion.vin = "WERTWEG454GS";
            automovil.otrosDatos = new OtrosDatos_type0();
            automovil.otrosDatos.nuevo = false;
            automovil.otrosDatos.uso = new ElementoCodificado();
            automovil.otrosDatos.uso.codigo = "3";
            //se agrega al request
            request.automovil = automovil;
            conductor.direccion = new Direccion();
            conductor.direccion.ciudad = "1";
            conductor.direccion.direccion = "CRA 1 5 30";
            conductor.direccion.departamento = "76";
            conductor.direccion.pais = "170";
            conductor.numeroDocumento = "24949999";
            conductor.telefono = new Telefono();
            conductor.telefono.numero = "4850000";
            conductor.tipoDocumento = new ElementoCodificado();
            conductor.tipoDocumento.codigo = "36";
            conductor.tipoDocumento.nombre = "Cedula Ciudadania";
            conductor.fechaNacimiento = Convert.ToDateTime("1950-11-06T00:00:00.000-06:00");
            conductor.genero = new ElementoCodificado();
            conductor.genero.codigo = "2";
            conductor.genero.nombre = "Mujer";
            conductor.ocupacion = new ElementoCodificado();
            conductor.ocupacion.codigo = "10";
            conductor.primerApellido = "Gutierrez";
            conductor.primerNombre = "Yesid";
            conductor.segundoApellido = "Hernandez";
            conductor.segundoNombre = "Pedro";
            request.conductor = conductor;


            datosGestion.agente = new ElementoCodificado();
            datosGestion.agente.codigo = "4091415";
            datosGestion.duracion = new ElementoCodificado();
            datosGestion.duracion.codigo = "0";
            datosGestion.formaPago = new ElementoCodificado();
            datosGestion.formaPago.codigo = "12";
            datosGestion.producto = new ElementoCodificado();
            datosGestion.producto.codigo = "6031";


            infoRequest.aplicacionCliente = "WEBCTZ";
            infoRequest.fecha = Convert.ToDateTime("2018-07-06T10:24:54.000-05:00");
            infoRequest.ip = "fe80::dc32:3:b8d:db9%14";
            infoRequest.requestID = "95194";
            infoRequest.terminal = "COBTA-I-AP4";



            PreguntaGeneral general = new PreguntaGeneral();
            Pregunta pregunta = new Pregunta();
            pregunta.codigo = "9008";
            pregunta.nombre = "";
            Respuesta rta = new Respuesta();
            rta.valor = "1";
            general.pregunta = pregunta;
            general.respuesta = rta;

            PreguntaGeneral[] preguntaPoliza = new PreguntaGeneral[] { general };
            request.preguntaPoliza = preguntaPoliza;


            PersonaNatural personaNatural = new PersonaNatural();
            personaNatural.direccion = new Direccion();
            personaNatural.direccion.ciudad = "1";
            personaNatural.direccion.departamento = "76";
            personaNatural.direccion.direccion = "CRA 1 5 30";
            personaNatural.direccion.pais = "170";
            personaNatural.numeroDocumento = "24949999";
            personaNatural.telefono = new Telefono();
            personaNatural.telefono.numero = "4850000";
            personaNatural.tipoDocumento = new ElementoCodificado();
            personaNatural.tipoDocumento.codigo = "36";
            personaNatural.tipoDocumento.nombre = "Cedula Ciudadanía";
            personaNatural.fechaNacimiento = Convert.ToDateTime("1950-11-06T00:00:00.000-06:00");
            personaNatural.genero = new ElementoCodificado();
            personaNatural.genero.codigo = "2";
            personaNatural.genero.nombre = "Mujer";
            personaNatural.ocupacion = new ElementoCodificado();
            personaNatural.ocupacion.codigo = "10";
            personaNatural.primerApellido = "Gutierrez";
            personaNatural.primerNombre = "Yesid";
            personaNatural.segundoApellido = "Hernandez";
            personaNatural.segundoNombre = "Pedro";
            PersonaNatural[] natural = new PersonaNatural[] { personaNatural };
            request.tomadorPersonaNatural = natural;


            return request;
        }


        public string XmlEncrypt()
        {
            var xml = new XmlDocument();
            xml.Load(@"C:\Users\desarrollador5\Desktop\request.xml");
            

            HttpWebRequest req = (HttpWebRequest)WebRequest.Create("https://wsqa.libertycolombia.com.co:8443/soa-infra/services/GenericAuto/GenericAutoQuotation/GenericAutoQuotationMediator_ep");
            req.Headers.Add("SOAPAction", "urn:quotationCarGeneric");
            req.Method = "POST";
            req.ContentType = "text/xml;charset=\"utf-8\"";

            using (Stream stream = req.GetRequestStream())
            {
                using (StreamWriter streamWriter = new StreamWriter(stream))
                {
                    streamWriter.Write(xml.OuterXml);

                }

            }
            try
            {
                WebResponse lol = req.GetResponse();
                StreamReader sr = new StreamReader(lol.GetResponseStream());
                var srString = sr.ReadToEnd();
            }
            catch (WebException webOs)
            {
                WebResponse lol = webOs.Response;
                StreamReader sr = new StreamReader(lol.GetResponseStream());
                var srString = sr.ReadToEnd();

            }

            return "";
        }

        public ActionResult About()
        {
            ViewBag.Message = "Your application description page.";

            return View();
        }

        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";

            return View();
        }
    }
}