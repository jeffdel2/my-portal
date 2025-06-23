$(document).ready(function() {
    $('#loginCoBtn').click(function() {
      $('#loginPopup').addClass('active');
    });
  
    $('#closeCoBtn').click(function() {
      $('#loginPopup').removeClass('active');
    });
  
    $('.popup-signin').click(function() {
      $('#initialView').addClass('hidden');
      $('#loginForm').removeClass('hidden');
    });

    if(window.location.hash){
        displayUserInfo();
    }
  });
  
  const auth0_clientID = 'ZCUkB8LfXb3hBnkFdUlc5Kpx86qGtS5Y';
  const auth0_domain = `auth-staples.desmaximus.com`;
  const redirect_uri = 'https://staplescom.democorp.xyz';
  const default_connection = 'Username-Password-Authentication';
  
  const auth0js = new auth0.WebAuth({
    domain: auth0_domain,
    clientID: auth0_clientID,
    responseType: 'id_token token',
    redirectUri: redirect_uri,
    scope: 'openid profile email'
  });

  function openSlideout() {
    document.getElementById("mySlideout").style.width = "250px";
  }

  function closeSlideout() {
    document.getElementById("mySlideout").style.width = "0";
  }
  
  function coauth_login_silent(realm, username, password) {
    let url = `https://${auth0_domain}/co/authenticate`;
  
    let data = {
      client_id: auth0_clientID,
      username: username,
      password: password,
      realm: realm,
      credential_type: "http://auth0.com/oauth/grant-type/password-realm"
    };
  
    const params = {
      headers: {
        'content-type': 'application/json'
      },
      method: 'POST',
      credentials: "include",
      body: JSON.stringify(data)
    };
  
    fetch(url, params)
      .then(data => data.json())
      .then(value => {
        let login_ticket = value['login_ticket'];
        console.log('login_ticket: ' + login_ticket);
 	window.location = "https://auth-staples.desmaximus.com/samlp/csLmrNO1rWjMH7N8qSZAEarhqH64bJzc" 
        /*
	      auth0js.authorize({login_ticket: login_ticket}, (err, result) => {
          if (err) showResult(err);
          else {
          }
        });
	*/
      })
      .catch(err => showResult('error in /co/authenticate call: ' + err));
  }
  
  function showResult(msg) {
    alert(msg);
  }
  
  function submitLogin() {
    let username = document.getElementById('username').value;
    let password = document.getElementById('password').value;
    coauth_login_silent(default_connection, username, password);
  }
  
  function displayUserInfo() {
    auth0js.parseHash({}, function(err, authResult) {
        if (err) {
            window.location.hash = "";
          return console.log(err);
          
        }
        window.location.hash = '';
        // The contents of authResult depend on which authentication parameters were used.
        // It can include the following:
        // authResult.accessToken - access token for the API specified by `audience`
        // authResult.expiresIn - string with the access token's expiration time in seconds
        // authResult.idToken - ID token JWT containing user profile information
        auth0js.client.userInfo(authResult.accessToken, function(err, user) {
            if (err) {
              console.error(err);
              return;
            }
            $('#userName').text(user.name);
            $('#userEmail').text(user.email);
            $('#userInfo').removeClass('hidden');
            $('#loginBtn').hide();
          });
      });

  }