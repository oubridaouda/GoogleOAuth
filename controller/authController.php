<?php

class AuthController
{

    public function googleAuthMethod($platform = "mobile")
    {

        //Authorize only post method
        $this->CommonFunction->methodAuthorizedInTheRequest('POST');

        $common = $this->CommonFunction;

        //Check the request methode and return invalid request if not POST method
        if (!$common->getRequestMethode("POST")) {
            //Display token invalidity message
            http_response_code(400);

            header('Access-Control-Allow-Origin: *');
            header('Content-Type:application/json');
            echo json_encode(['message' => 'invalid request']);
            die;
        }


        //Check if input is exist and not empty
        if (!isset($_POST['email']) || !isset($_POST['username']) || empty($_POST['email']) || empty($_POST['username'])) {

            $array = array(
                'code' => 404,
                'message' => 'veuillez remplir tous les champs',
                "data" => []
            );
            header("Content-type: application/json; charset=utf-8");
            echo json_encode($array);
            die;
        }

        $email = htmlspecialchars(trim($_POST['email']));
        $username = htmlspecialchars(trim($_POST['username']));


        //Check the request methode and return invalid request if not POST method
        if (!$common->emailRegexValidator($email)) {
            $array = array(
                'code' => 500,
                'message' => 'Votre email est incorrecte.',
                "data" => []
            );
            header("Content-type: application/json; charset=utf-8");
            echo json_encode($array);
            die;
        }

        $googleUser = $this->authModel->findUserOnTable($email);


        if (!empty($googleUser)) {
            $this->googleLoginAction($googleUser[0], $platform);
            die;
        }

        $this->googleSignUpAction($email, $username, $platform);
        die;
    }

//Login with google
    private function googleLoginAction($userData, $platform = "mobile")
    {
        //Save user information in token
        $payload = [
            'user_id' => $userData['id'],
            'email' => $userData['email']
        ];

        $jwtToken = $this->jwt->createNewJWT([], $payload);

        if ($platform === "web") {
            return true;
        }

        $array = array(
            'code' => 200,
            'message' => 'Vous êtes bien connectés.',
            "data" => [
            ]
        );
        header("Content-type: application/json; charset=utf-8");
        echo json_encode($array);
        die;
    }

//Sign Up with google
    private function googleSignUpAction($email, $username, $platform = "mobile")
    {
        $addGoogleUser = $this->authModel->addNewGoogleUser($email, $username);

        if (!$addGoogleUser && $platform === "mobile") {
            $array = array(
                'code' => 500,
                'message' => "Une erreur s'est produite ! Veuillez réessayer plus tard.",
                "data" => []
            );
            header("Content-type: application/json; charset=utf-8");
            echo json_encode($array);
            die;
        }

        if (!$addGoogleUser && $platform === "web") {
            return false;
        }

        $newGoogleUserData = $this->authModel->findUserOnTable($email);

        //Save user information in token
        $payload = [
            'user_id' => $newGoogleUserData[0]['id'],
            'email' => $newGoogleUserData[0]['email']
        ];

        $jwtToken = $this->jwt->createNewJWT([], $payload);

        if ($addGoogleUser && $platform === "web") {
            return true;
        }

        $array = array(
            'code' => 200,
            'message' => 'Votre compte a bien été créer.',
            "data" => [
            ]
        );
        header("Content-type: application/json; charset=utf-8");
        echo json_encode($array);
        die;
    }

    public function googleSignInPage()
    {
        $this->googleWebAuth();
        $this->CommonFunction->displayView('googleAuth');
    }

//Web auth with google
    public function googleWebAuth()
    {
        $googleUserAuth = false;
        if (
            isset($_POST['g_csrf_token']) &&
            !empty($_POST['g_csrf_token']) ||
            isset($_COOKIE['g_csrf_token']) &&
            !empty($_COOKIE['g_csrf_token']) &&
            $_COOKIE['g_csrf_token'] == $_POST['g_csrf_token']
        ) {
            //Website client id in google console
            $clientId = "YOUR_CLIENT_ID";
            $client = new Google_Client(['client_id' => $clientId]);  // Specify the CLIENT_ID of the app that accesses the backend

            //User google jwt token
            $idToken = $_POST["credential"];
            $user = $client->verifyIdToken($idToken);

            //Check if user exist
            if (!isset($user['email'])) {
                echo "user does not exist";
                exit;
            }

            //Check if user exist in database
            $googleUser = $this->authModel->findUserOnTable($user['email']);

            //If user exist in database we login in her account
            if (!empty($googleUser)) {
                $googleUserAuth = $this->googleLoginAction(["email" => $user['email'], "username" => $user['name'], "id" => $user['sub']], "web");
            }

            //If user does not exist in database we create new user account
            if (empty($googleUser)) {
                $googleUserAuth = $this->googleSignUpAction($user['email'], $user['name'], "web");
            }
        }

        //If user auth with success we return success auth page
        if ($googleUserAuth) {
            echo "success connected";
            //return your homepage
            die;
        }
    }
}