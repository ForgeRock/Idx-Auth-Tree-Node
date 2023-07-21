# Daon IdentityX SaaS Onboarding Node

Daon's IdentityX platform is helping customers across the globe ditch passwords and deliver world-class customer
 experience by leveraging biometrics. This node allows ForgeRock customers to easily add Daon SaaS On Boarding status
 checks to authentication trees.

## About Daon ##
Daon, [www.daon.com](www.daon.com), is an innovator in developing and deploying biometric authentication and identity assurance solutions worldwide. Daon has pioneered methods for securely and conveniently combining biometric and identity capabilities across multiple channels with large-scale deployments that span payments verification, digital banking, wealth, insurance, telcos, and securing borders and critical infrastructure. Daon's IdentityX® platform provides an inclusive, trusted digital security experience, enabling the creation, authentication and recovery of a user’s identity and allowing businesses to conduct transactions with any consumer through any medium with total confidence. Get to know us on [Twitter](https://twitter.com/DaonInc), [Facebook](https://www.facebook.com/humanauthentication) and [LinkedIn](https://www.linkedin.com/company/daon).

## IdentityX SaaS Onboarding ##

Daon's IdentityX SaaS Onboarding provides the functionality required to support prospective tenants of an existing IdentityX system who want to collect, assess and evaluate the supported data provided as part of a new customer application process. In a typical scenario, applicants can apply for an account by simply taking a selfie for enrollment, then scanning their documents, and performing liveness checks.

## Installation ##
Copy the .jar file from the ../target directory into the ../web-container/webapps/openam/WEB-INF/lib directory where AM is deployed.  Restart the web container to pick up the new node.  The node will then appear in the authentication trees components palette.

## USING THE NODE IN YOUR TREE ##

### There is one node included ###
- **Daon SaaS On Boarding Node** This node redirects to the Daon SaaS Onboarding site, where the user will go through the process of taking a selfie and scanning their documents. When the Onboarding is complete, successful or not, the flow will redirect back to this node to process the Onboarding outcome.

### IDENTITYX SERVER DETAILS ###
The node must be configured to work with an IdentityX server. Contact your Daon representative for details.

### Configuration Parameters ###
Daon Saas Onboarding Node contains the following configurable parameters:
- **Hostname** The hostname of the server where Daon SaaS Onboarding resides (obtained from Daon)
- **Tenant Name** Your client ID 
- **Redirect URI** When onboarding is complete, the Onboarding site will redirect here
- **Client Secret** A value agreed upon with Daon that allows the code at the redirect URI to obtain the IDToken from the Daon Onboarding services
- **Login Hint Field** The name of the field in shared storage that contains the desired username for the user being onboarded

The image below shows an example authentication tree using the Daon SaaS On Boarding node.
![ScreenShot](./images/daon_saas_onboarding.png)
        

## SUPPORT ##
For more information on this node or to request a demonstration, please contact:
Jason Beloncik - jason.beloncik@daon.com