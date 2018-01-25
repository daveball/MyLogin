﻿using MyLogin.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Security.Claims;
using MyLogin.CustomLibraries;

namespace MyLogin.Controllers
{
    [AllowAnonymous]
    public class AuthController : Controller
    {
        // GET: Auth
       
        [HttpGet]
        public ActionResult Login()
        {
           
            return View();
        }

        [HttpPost]
        public ActionResult Login(Users model)
        {   if (!ModelState.IsValid)
            {
                return View(model);
            }
            using (var db = new MainDbContext()) {

                var emailCheck = db.Users.FirstOrDefault(u => u.Email == model.Email);
                var getPassword = db.Users.Where(u => u.Email == model.Email).Select(u => u.Password);
                var materializePassword = getPassword.ToList();
                var password = materializePassword[0];
                var decryptedPassword = CustomDecrypt.Decrypt(password);

                if (model.Email !=null && model.Password == decryptedPassword)
                {
                    var getName = db.Users.Where(u => u.Email == model.Email).Select(u => u.Name);
                    var materializeName = getName.ToList();
                    var name = materializeName[0];

                    var getCountry = db.Users.Where(u => u.Email == model.Email).Select(u => u.Country);
                    var materializeCountry = getCountry.ToList();
                    var country = materializeCountry[0];

                    var getEmail = db.Users.Where(u => u.Email == model.Email).Select(u => u.Email);
                    var materializeEmail = getEmail.ToList();
                    var email = materializeEmail[0];

                    var identity = new ClaimsIdentity(new[] {
                                new Claim(ClaimTypes.Name, name),
                                new Claim(ClaimTypes.Email, email),
                                new Claim(ClaimTypes.Country, country)

                    }                    , "ApplicationCookie");
                    var ctx = Request.GetOwinContext();
                    var authManager = ctx.Authentication;
                    authManager.SignIn(identity);
                    return RedirectToAction("Index","Home");

                }
            }
            ModelState.AddModelError("", "Invalid Email or Password");
            return View(model);
        }

        public ActionResult Logout()
        {
            var ctx = Request.GetOwinContext();
            var authManager = ctx.Authentication;

            authManager.SignOut("ApplicationCookie");
            return RedirectToAction("Login", "Auth");
        }
        public ActionResult Registration()
        {
            return View();
        }

        [HttpPost]
        public ActionResult Registration(Users model)
        {
            if (ModelState.IsValid)
            {
                using (var db = new MainDbContext())
                {
                    var encryptedPassword = CustomEncrypt.Encrypt(model.Password);
                    var user = db.Users.Create();
                    user.Email = model.Email;
                    user.Password = encryptedPassword;
                    user.Country = model.Country;
                    user.Name = model.Name;
                    db.Users.Add(user);
                    db.SaveChanges();

                }
            }
            else
            {
                ModelState.AddModelError("", "One or more fields have been");
            }
            return View();
        }

        [HttpGet]
        public ActionResult Index()
        {
            var db = new MainDbContext();
            return View(db.Lists.Where(x => x.Public == "YES").ToList());
        }
        /*
        private string  GetRedirectUrl( string returnUrl)
        {
            if(string.IsNullOrEmpty(returnUrl) || Url.IsLocalUrl(returnUrl))
            {
                return Url.Action("Index", "Home");
            }
            return returnUrl;
        }*/

    }
}