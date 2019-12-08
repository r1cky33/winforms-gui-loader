<?php
include('helper.php');

// Load Request
$api_method = isset($_POST['api_method']) ? $_POST['api_method'] : '';
$api_data = isset($_POST['api_data']) ? $_POST['api_data'] : '';

// Validate Request
if (empty($api_method) || empty($api_data)) {
    API_Response(true, 'Invalid Request');
}
if (!function_exists($api_method)) {
    API_Response(true, 'API Method Not Implemented');
}

// Call API Method
call_user_func($api_method, $api_data);

/* Helper Function */

function API_Response($isError, $errorMessage, $responseData = '')
{
    exit(json_encode(array(
        'IsError' => $isError,
        'ErrorMessage' => $errorMessage,
        'ResponseData' => $responseData
    )));
}

/* API Methods */

function loginTest($api_data)
{
    // Decode Login Data
    $login_data = json_decode($api_data);

    $conn = mysqli_connect('localhost', 'root', '', 'tarab_test');

    if(mysqli_connect_errno()){
        API_Response(true, 'MySQL connection failure!');
    }

    $result = mysqli_query($conn, "SELECT usrname, usrpassword FROM login WHERE usrname = '$login_data->username'");

    if(!$result){
        API_Response(true, 'MySQL no result!');
    }

    while($row = mysqli_fetch_row($result)){
        if($row[0] == $login_data->username && $row[1] == $login_data->password){
            API_Response(false, '', 'SUCCESS');
        }
    }

    API_Response(true, 'Invalid username and/or password.');
}

function reqBin($api_data){
    $login_data = json_decode($api_data);

    $conn = mysqli_connect('localhost', 'root', '', 'tarab_test');

    if(mysqli_connect_errno()){
        API_Response(true, 'MySQL connection failure!');
    }

    $result = mysqli_query($conn, "SELECT usrname, usrpassword FROM login WHERE usrname = '$login_data->username'");

    if(!$result){
        API_Response(true, 'MySQL no result!');
    }

    while($row = mysqli_fetch_row($result)){
        if($row[0] == $login_data->username && $row[1] == $login_data->password){
            $file = 'sample.dll';
            if (file_exists($file)) {
                readfile($file);
                exit;
            }
        }
    }

    API_Response(true, 'Invalid username and/or password.');
}

?>