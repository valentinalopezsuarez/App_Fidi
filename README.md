# Cloud-Land-sample-backend

Web backend with custom sign-in, sign-up, forgot password, change details and change password screens, using App ID Cloud Directory APIs.

![Cloud-Land-login-screen](/backend/public/images/cloud_land_login_screen.png)

## Before running 

### Create and configure App ID service

1. Create App ID service from the [IBM Cloud services catalog](https://console.bluemix.net/catalog/services/app-id?taxonomyNavigation=apps) and name it _CloudLandAppIDService_.
2. In the App ID dashboard click on **Workflow Templates** under **Cloud Directory** and scroll down. 
3. Name your backend host and set the _Thank You page URL_ to

_https://Your-Cloud-Land-Backend.mybluemix.net/ibm/cloud/appid/view/account_confirmed_

after replacing "Your-Cloud-Land-Backend" with your backend host name.

4. Navigate to the **Reset password** tab, Set the _Reset password page URL_ to

_https://Your-Cloud-Land-Backend.mybluemix.net/ibm/cloud/appid/view/reset_password_form_

after replacing "Your-Cloud-Land-Backend" with your backend host name.

## Deploying the sample to IBM Cloud

1. Download the **backend** folder.
2. Replace the "YOUR SPACE" with your space in the following command and run it: 
```
bx resource service-alias-create "CloudLandAppIDService-alias" --instance-name "CloudLandAppIDService" -s "YOUR SPACE" 
```
3. Go to [manifest.yml](/backend/manifest.yml) and replace the Your-Cloud-Land-Backend in the _host_ property with your own host name (same name that was picked in step 3 above).
4. Open terminal at the **backend** folder and run: 
```
bx app push 
```
5. Open the browser and go to: 
_https://Your-Cloud-Land-Backend.mybluemix.net_ 
after replacing "Your-Cloud-Land-Backend" with your backend host name


Note:
If your App ID service is NOT deployed on US region: 
1. Go to [manifest.yml](/backend/manifest.yml) and change the _domain_ property according to the region your App ID service is deployed.
2. Change the domain in the **Custom Landing pages** accordingly.
    
