using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Web;
using System.Web.Mvc;
using Thinktecture.IdentityModel.Mvc;

namespace AltLanDS.Beeline.Identity.MVCClient.Controllers
{
    public class HomeController : Controller
    {
        // GET: Home
        public ActionResult Index()
        {
            var currentUser = Request.GetOwinContext().Authentication.User;
            ViewBag.IsAuthenticated = currentUser.Identity.IsAuthenticated;
            return View();
        }

        [Authorize]
        public ActionResult LogIn()
        {
            return Redirect("/");
        }

        public ActionResult Logout()
        {
            Request.GetOwinContext().Authentication.SignOut();
            return Redirect("/");
        }

        private void SetTempState(string state, string nonce)
        {
            var tempId = new ClaimsIdentity("TempState");
            tempId.AddClaim(new Claim("state", state));
            tempId.AddClaim(new Claim("nonce", nonce));

            Request.GetOwinContext().Authentication.SignIn(tempId);
        }


        [ResourceAuthorize("Read", "ContactDetails")]
        public ActionResult AboutCurrentUser()
        {
            return View((User as ClaimsPrincipal).Claims);
        } 
    }
}