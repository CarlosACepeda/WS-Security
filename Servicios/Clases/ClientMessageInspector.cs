using Servicios.Clases;
using System;
using System.Collections.Generic;
using System.Linq;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Dispatcher;
using System.Web;

namespace Servicios.Clases
{
    /// <summary>
    /// Implementando la interfaz, permite cambiar cualquier elemento del mensaje en el lado del cliente antes de enviarlo al servidor.
    /// </summary>
    public class ClientMessageInspector : IClientMessageInspector
    {
        public void AfterReceiveReply(ref Message reply, object correlationState)
        {
            reply = DecryptXmlResponse.GetDecryptedResponse(ref reply);
        }

        public object BeforeSendRequest(ref Message request, IClientChannel channel)
        { 
            //Enviamos el request al siguiente método para firmarlo.
            request= ProcessXmlRequest.GetSignedRequest(ref request);
            return request;
        }
    }
}