// import * as dotenv from 'dotenv';
// import { Body, Controller, Get, Injectable, Post, Put, Query, Req, Res } from '@nestjs/common';
// import * as OAuthClient from 'intuit-oauth';
// import * as crypto from 'crypto';
// import { Response, Request } from 'express';
// import axios from 'axios';
// import { Credentials } from './QucikBook-Db.entity';
// import { InjectRepository } from '@nestjs/typeorm';
// import { Repository } from 'typeorm';
// import { log } from 'console';

// dotenv.config();


// @Controller('quickbook')
// export class QuickbookController {
//   private oauthClient: OAuthClient;

//   constructor(
//     @InjectRepository(Credentials)
//     private credentialsRepository: Repository<Credentials>,
//   ) {}

//   @Get('authorize')
//   async authorize(@Res() res: Response) {
//     const clientId: string = process.env.CLIENT_ID;
//     const clientSecret: string = process.env.CLIENT_SECRET;
//     const redirectUri: string = process.env.REDIRECT_URI;

//     if (!clientId || !clientSecret || !redirectUri) {
//       return res.status(500).send('Missing environment variables');
//     }

//     const states = crypto.randomBytes(8).toString('hex');

//     this.oauthClient = new OAuthClient({
//       clientId,
//       clientSecret,
//       redirectUri,
//     });

//     const authUri = this.oauthClient.authorizeUri({
//       scope: [OAuthClient.scopes.Accounting, OAuthClient.scopes.OpenId],
//       state: states,
//     });

//     res.redirect(authUri);
//   }

//   @Get('callback')
//   async quickbookcallback(@Req() req: Request, @Res() res: Response): Promise<any> {
//     const clientId: string = process.env.CLIENT_ID;
//     const clientSecret: string = process.env.CLIENT_SECRET;
//     const redirectUri: string = process.env.REDIRECT_URI;

//     const parseRedirect = req.url;
//     const urlParams = new URLSearchParams(parseRedirect.split('?')[1]);
//     const authCode = urlParams.get('code');

//     if (!authCode) {
//       return res.status(400).send('Authorization code is missing');
//     }

//     try {
//       const tokenRequestData = {
//         code: authCode,
//         redirect_uri: redirectUri,
//         grant_type: 'authorization_code',
//         client_id: clientId,
//         client_secret: clientSecret,
//       };

//       const requestBody = new URLSearchParams(tokenRequestData).toString();

//       const tokenResponse = await axios.post(
//         'https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer',
//         requestBody,
//         {
//           headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
//         },
//       );

//       const accessToken = tokenResponse.data.access_token;
//       const refreshToken = tokenResponse.data.refresh_token;

//       if (!accessToken || !refreshToken) {
        
//       }

//       await this.save(clientId, clientSecret, accessToken, refreshToken);

//       res.send('Authorization successful. Tokens generated.');
//     } catch (err) {
//       res.status(500).send('Authorization failed.');
//     }
//   }


// private async refreshAccessToken(refreshToken: string) {
//   const clientId: string = process.env.CLIENT_ID;
//   const clientSecret: string = process.env.CLIENT_SECRET;
//   const redirectUri: string = process.env.REDIRECT_URI;

//   const tokenRequestData = {
//     grant_type: 'refresh_token',
//     refresh_token: refreshToken,
//     client_id: clientId,
//     client_secret: clientSecret,
//     redirect_uri: redirectUri,
//   };

//   const requestBody = new URLSearchParams(tokenRequestData).toString();

//   try {
//     const tokenResponse = await axios.post(
//       'https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer',
//       requestBody,
//       {
//         headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
//       }
//     );

//     const accessToken = tokenResponse.data.access_token;
//     const newRefreshToken = tokenResponse.data.refresh_token;
//     console.log("new refresh token :" , newRefreshToken)



//     if (!accessToken || !newRefreshToken) {
//       throw new Error('Failed to refresh tokens');
//     }
    
    

//     return { accessToken, refreshToken: newRefreshToken };
//   } catch (error) {
//     console.error('Error refreshing access token:', error);
//     throw error;
//   }}


  
//   private async save(clientId: string, clientSecret: string, accessToken: string, refreshToken: string) {
//     const credentials = new Credentials();
//     credentials.client_id = clientId;
//     credentials.client_secret = clientSecret;
//     credentials.refresh_token = refreshToken;
//     credentials.access_token = accessToken;

//     await this.credentialsRepository.save(credentials);
//   }

//   // private async updateToken(accessToken:string,refreshToken:string){
//   //   const authDetails = await this.credentialsRepository.findOne({ order: { id: 'DESC' } });

//   //   if (!authDetails){

//   //     const updateToken=new this.credentialsRepository.create()

//   //   }
//   // }
  

//   private async getQuickBooksToken(): Promise<string | null> {
//     const credentials = await this.credentialsRepository.findOne({where:{}});

//     if (credentials) {
      
//       return credentials.access_token;
//     }

    
//   }

//   @Post('account')
//   async createAccount(@Body() accountData: any, @Res() res: Response) {
//     try {

//       const token = await this.getQuickBooksToken();
//       console.log("mic test :","{{{{{{", token,"}}}}}}")
//       if (!token) {
//         return res.status(400).send("No QuickBooks token available");
//       }
//       const authDetail =await this.credentialsRepository.find({
//         order:{
//           id:'DESC'
//         }
//       })

//       const smackId = process.env.SMACK_ID; 
//       console.log("mic check 2 : ", smackId);
      
//       if (!smackId) {
//         return res.status(400).send("SMACK_ID is not configured.");
//       }
//       console.log("Authdata",authDetail[0]);
      

//       const response = await axios.post(
//         `https://sandbox-quickbooks.api.intuit.com/v3/company/${smackId}/account`,
//         accountData,
//         {
//           headers: {
//             'Authorization': `Bearer ${authDetail[0].access_token}`,
//             'Content-Type': 'application/json',
//             Accept:'application/json'
//           },
//         },
//       );
//       console.log("mic check 3 :", response);
      

//       return res.status(201).send(response.data);
//     } catch (err) {
//         console.log("iam here your problem");
//         console.log(err);
        
//         return res.status(err.response.status).send(err.response.data);
        
     
//     }

//  }

//  @Get('accounts')
//  async getAccounts(@Body() accountData: any, @Res() res: Response) {
 
//   try { const token = await this.getQuickBooksToken();
//     console.log("mic test :","{{{{{{", token,"}}}}}}")
//     if (!token) {
//       return res.status(400).send("No QuickBooks token available");
//     }
//     const authDetail =await this.credentialsRepository.find({
//       order:{
//         id:'DESC'
//       }
//     })
//     await this.refreshAccessToken(authDetail[0].refresh_token);

//     const accessToken=authDetail[0].access_token;
//     const smackId = process.env.SMACK_ID; 
//     console.log("mic check 2 : ", smackId);
    
//     if (!smackId) {
//       return res.status(400).send("SMACK_ID is not configured.");
//     }
//     console.log("Authdata",authDetail[0]);

//     const query = encodeURIComponent("SELECT * FROM Account ")
    

//     const response = await axios.get(
//       `https://sandbox-quickbooks.api.intuit.com/v3/company/${smackId}/query?query=${query}`,
//       {
//         headers: {
//           Authorization: `Bearer ${accessToken}`, 
//           'Content-Type': 'text/plain',
//           Accept: 'application/json',
//         },
//       }
//     );
//     console.log("mic check 3 :", response);
    

//     return res.status(201).send(response.data);
//   } catch (err) {
//       console.log("iam here your problem");
//       console.log(err);
      
//       return res.status(err.response.status).send(err.response.data);
      
   
//   }

//  }
 
//  @Get('accountsById')
// async getAccountsById(@Query('id') Id: string, @Res() res: Response) {
//   try {
//     const token = await this.getQuickBooksToken();
//     console.log("Token:", token);

//     if (!token) {
//       return res.status(400).send("No QuickBooks token available");
//     }

//     const authDetail = await this.credentialsRepository.find({
//       order: {
//         id: 'DESC',
//       },
//     });

//     const accessToken = authDetail[0].access_token;
//     const smackId = process.env.SMACK_ID;

//     console.log("SMACK_ID:", smackId);

//     if (!smackId) {
//       return res.status(400).send("SMACK_ID is not configured.");
//     }

//     console.log("Auth Data:", authDetail[0]);

//     if (!Id) {
//       return res.status(400).send("Account ID is required");
//     }

//     const response = await axios.get(
//       `https://sandbox-quickbooks.api.intuit.com/v3/company/${smackId}/account/${Id}?minorversion=73`,
//       {
//         headers: {
//           Authorization: `Bearer ${accessToken}`,
//           'Content-Type': 'application/json',
//           Accept: 'application/json',
//         },
//       },
//     );

//     console.log("QuickBooks API Response:", response.data);

//     return res.status(201).send(response.data);
//   } catch (err) {
//     console.error("Error:", err);
//     return res.status(err.response?.status || 500).send(err.response?.data || 'Internal server error');
//   }
// }

// @Post('updateAccount')
// async updateAccount(@Query('id')Id: string, @Body() accountData: any, @Res() res: Response) {
//   try {
//     const token = await this.getQuickBooksToken();
//     if (!token) {
//       return res.status(400).send("No QuickBooks token available");
//     }

//     // Fetch the most recent credentials
//     const authDetail = await this.credentialsRepository.find({
//       order: { id: 'DESC' },
//     });

//     const accessToken = authDetail[0].access_token;
//     const smackId = process.env.SMACK_ID;

//     if (!smackId) {
//       return res.status(400).send("SMACK_ID is not configured.");
//     }

//     // Ensure the SyncToken is passed with the request body
//     const syncToken = accountData.yncToken; 
//     console.log("error here" , syncToken);
    
//     if (!syncToken) {
//       return res.status(400).send("SyncToken is required.");
//     }

//     // Prepare the request body for updating the account
//     const updatedAccountData = {
//       "Account": {
//         "Id": accountData.Id, // Existing Account ID
//         "SyncToken": syncToken, // Correct SyncToken
//         "FullyQualifiedName": accountData.FullyQualifiedName, // Updated Name
//         "Active": accountData.Active,
//         "AccountType": accountData.AccountType,
//         "AccountSubType": accountData.AccountSubType,
//       }
//     };

//     // Sending the PUT request to update the account
//     const response = await axios.put(
//       `https://sandbox-quickbooks.api.intuit.com/v3/company/${smackId}/account/${Id}?minorversion=73`,
//       updatedAccountData,
//       {
//         headers: {
//           Authorization: `Bearer ${accessToken}`,
//           'Content-Type': 'application/json',
//           Accept: 'application/json',
//         },
//       }
//     );

//     // Sending the response from QuickBooks API
//     return res.status(200).send(response.data);
//   } catch (err) {
//     console.error("Error:", err);
//     return res.status(err.response?.status || 500).send(err.response?.data || 'Internal server error');
//   }
// }


// }
