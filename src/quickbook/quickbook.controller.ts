import { Controller , Get ,Post, Res, Req, Body, Param} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import{ Credentials} from '../schema/quickbook.schema'
import { Request,response,Response } from 'express';
import { Model} from'mongoose';
import axios from 'axios';
import * as env from 'dotenv';
import * as OAuthClient from 'intuit-oauth';
import * as crypto from 'crypto';
import qs from 'querystring';
env.config();

@Controller('quickbook')
export class QuickbookController {
   private oauthClient:OAuthClient;
  
  constructor (
    @InjectModel (Credentials.name)
    private credentailsModel:Model<Credentials>
            
    ){}
    @Get('auth')
    async authorize(@Res() res: Response) {
            console.log("Running auth success");
        
    const clientId :string= process.env.CLIENT_ID as string;
    const clientSecret:string = process.env.CLIENT_SECRET as string;
    const redirectUri:string = process.env.REDIRECT_URI as string;
    console.log(clientId);
    console.log(clientSecret);
    console.log(redirectUri)
    if (!clientId || !clientSecret || !redirectUri ) {
      return res.status(500).send('Missing environment variables');
    }
    const headerStatus= crypto.randomBytes(8).toString('hex');
    this.oauthClient = new OAuthClient({
      clientId,
      clientSecret,
      redirectUri,
      environment: 'sandbox',
      });
      console.log("hs "+headerStatus)
      const authUri = this.oauthClient.authorizeUri({
      scope: [OAuthClient.scopes.Accounting,  OAuthClient.scopes.OpenId],
      state: headerStatus,
      })
    
      console.log(authUri);
      res.redirect(authUri);
     
    }      
      @Get('callback')
      async quickbookcallback(@Req() req:Request, @Res() res:Response){
      const clientId:string = process.env.CLIENT_ID as string;
      const clientSecret: string=process.env.CLIENT_SECRET as string;
      const redirect_uri: string =process.env.REDIRECT_URI as string;

      console.log(clientId);
      console.log(clientSecret);
      //console.log(redirect)
      const parseRedirect= req.url;
      const urlParams=new URLSearchParams(parseRedirect.split('?')[1]);
      const authcode=urlParams.get("code")as string;
      if(!authcode){
        return res.status(400).send("No token assigned for callback");
      }
      try{
        console.log("entry in callback try")
        const tokenResponse ={
        grant_type:'authorization_code',
        code:authcode,
        redirect_uri:redirect_uri,}

        const reqBody = new URLSearchParams(tokenResponse).toString();
        const basic = "Basic " + Buffer.from(clientId + ":" + clientSecret).toString('base64');
        console.log(basic);
        const tokenForResponse = await axios.post(
          'https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer', reqBody,
        
        {
          headers:{
            Authorization:basic,
            'Content-Type':'application/x-www-form-urlencoded'
          },
        }
      );
        console.log("Token :" ,tokenForResponse);

        const accessToken=tokenForResponse.data.access_token;
        const refreshToken=tokenForResponse.data.refresh_token;
        if(!accessToken ||!refreshToken){
        }
        await this.save(clientId,clientSecret,accessToken,refreshToken);
        res.status(201).send("Authorization success.")
      }catch(error){
          res.status(500).send(error);
         
          console.log(error);
        }
      }


     private async refreshAccessToken(refreshToken: string) {
    const clientId: string = process.env.CLIENT_ID as string;
    const clientSecret: string = process.env.CLIENT_SECRET as string;

    const tokenReqData = {
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
    };

    const tokenReq = new URLSearchParams(tokenReqData).toString();
    const basicAuth = "Basic " + Buffer.from(clientId + ":" + clientSecret).toString('base64');

    try {
        const tokenResponse = await axios.post(
            'https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer',
            tokenReq,
            {
                headers: {
                    Authorization: basicAuth,
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
            }
        );

        const newAccessToken = tokenResponse.data.access_token;
        const newRefreshToken = tokenResponse.data.refresh_token;

        // Update database with new tokens
        await this.credentailsModel.findOneAndUpdate(
            { refreshToken: refreshToken }, 
            { accessToken: newAccessToken, refreshToken: newRefreshToken }
        );

        return { newAccessToken, newRefreshToken };
    } catch (err) {
        throw new Error("Could not refresh token, please reauthenticate.");
    }
}


      private async save(clientId:string,clientSecret:string,accessToken:string,refreshToken:string){
        const credentials=new Credentials();
        credentials.clientId=clientId,
        credentials.clientSecret=clientSecret,
        
        credentials.accessToken=accessToken;
        credentials.refreshToken=refreshToken;
        const newCredentials=new this.credentailsModel(credentials);
        newCredentials.save();
        }
        
        private async isExpired(accessToken: string): Promise<boolean> {
          try {
              const companyId = process.env.COMPANY_ID;
              if (!companyId) throw new Error("Missing Company ID");
      
              await axios.get(
                  `https://sandbox-quickbooks.api.intuit.com/v3/company/${companyId}/account`,
                  {
                      headers: {
                          "Authorization": `Bearer ${accessToken}`,
                          "Content-Type": "application/json",
                      }
                  }
              );
      
              return false; // Token is valid
          } catch (error) {
              return error.response?.status === 401; // Return true if unauthorized (expired)
          }
      }
      

       private async quickBookToken(): Promise<string> {
    const credential = await this.credentailsModel.findOne().sort({ _id: -1 });
    if (!credential) {
        throw new Error("No stored credentials found");
    }

    if (await this.isExpired(credential.accessToken as string)) {
        // Auto-refresh without alert
        const { newAccessToken } = await this.refreshAccessToken(credential.refreshToken as string);
        return newAccessToken;
    }

    return credential.accessToken as string;
}
/////////////////////ACCOUNT//////////////////////
        @Post('account/create')
        async createAccount(@Body() accountDetail:any, @Res() res:Response){
          try{
            const token=await this.quickBookToken();
            if(!token) 
              res.status(400).send("No token for create account")
            const company_Id=process.env.COMPANY_ID;
            console.log("Company_Id:",company_Id);
            console.log(accountDetail)
            if(!company_Id) 
              return res.status(400).send("Company id not valid and non config")
            const response=await axios.post(`https://sandbox-quickbooks.api.intuit.com/v3/company/${company_Id}/account`, 
              accountDetail,
              {
              headers:{
                'Authorization':`Bearer ${token}`,
                'Content-Type':'application/json',
                 Accept:'application/json',
              }
            }
          );
          res.status(200).send(response.data)
          }catch(error) {
           console.log(error);
            res.status(500).send("Internal Server Error")
          }
        }

      

        @Get('account/getQuery')
        async queryAccount( @Req() req: Request, @Res() res: Response) {
            try {
                const token = await this.quickBookToken();
                if (!token) {
                    return res.status(400).send("No token available for query");
                }
        
                const company_Id = process.env.COMPANY_ID;
                if (!company_Id) {
                    return res.status(400).send("Company ID is missing or not configured");
                }
        
               
                const queryString = encodeURIComponent("select * from Account Where Metadata.CreateTime>'2025-03-24T00:02:52-07:00'")
        
                const response = await axios.get(
                    `https://sandbox-quickbooks.api.intuit.com/v3/company/${company_Id}/query?query=${queryString}`,
                    {
                        headers: {
                            'Authorization': `Bearer ${token}`,
                            'Content-Type': 'application/json',
                            Accept: 'application/json',
                        },
                    }
                );
        
                res.status(200).send(response.data);
            } catch (error) {
                console.error("QuickBooks API Query Error:", error.response?.data || error.message);
                res.status(error.response?.status || 500).send({
                    message: "Error in querying QuickBooks",
                    error: error.response?.data || error.message,
                });
            }
        }


        @Post('account/get/:id')
        async getAccount(@Param('id') id:string ,@Req() req:Request,@Res() res:Response){
            try{
                const token = await this.quickBookToken();
                if (!token) {
                    return res.status(400).send("No token available for query");
                }
        
                const company_Id = process.env.COMPANY_ID;
                if (!company_Id) {
                    return res.status(400).send("Company ID is missing or not configured");
                }

                const response = await axios.get(
                    `https://sandbox-quickbooks.api.intuit.com/v3/company/${company_Id}/account/${id}?minorversion=75`,
                    {
                        headers: {
                            'Authorization': `Bearer ${token}`,
                            'Content-Type': 'application/json',
                            Accept: 'application/json',
                        },
                    }
                );
        
                res.status(200).send(response.data);
            } catch (error) {
                console.error("QuickBooks API Read Error:", error.response?.data || error.message);
                res.status(error.response?.status || 500).send({
                    message: "Error in Reading QuickBooks",
                    error: error.response?.data || error.message,
                });
            }
        
        }
        @Post('account/update')
        async updateAccount(@Body() account:any,@Res() res:Response){
            try{
                const token = await this.quickBookToken();
                if (!token) {
                    return res.status(400).send("No token available for query");
                }
        
                const company_Id = process.env.COMPANY_ID;
                if (!company_Id) {
                    return res.status(400).send("Company ID is missing or not configured");
                }

                const response = await axios.post(
                    `https://sandbox-quickbooks.api.intuit.com/v3/company/${company_Id}/account?minorversion=75`,
                    account,
                    {
                        headers: {
                            'Authorization': `Bearer ${token}`,
                            'Content-Type': 'application/json',
                            Accept: 'application/json',
                        },
                    }
                );
                
                res.status(200).send(response.data);
            } catch (error) {
                console.error("QuickBooks API Upadating Error:", error.response?.data || error.message);
                res.status(error.response?.status || 500).send({
                    message: "Error in Updating QuickBooks",
                    error: error.response?.data || error.message,
                });
            }
        
        }

//////////////////////////////BILLING///////////////////////////

@Get('vendors')
async getVendors(@Res() res: Response) {
    try {
        const token = await this.quickBookToken();
        if (!token) {
            return res.status(400).send("No token available for query");
        }

        const company_Id = process.env.COMPANY_ID;
        const response = await axios.get(
            `https://sandbox-quickbooks.api.intuit.com/v3/company/${company_Id}/query?query=SELECT * FROM Vendor`,
            {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Accept': 'application/json',
                },
            }
        );
        const vendor = response.data.QueryResponse.Vendor || []
        res.status(200).send(response.data.QueryResponse.Vendor || []);
        console.log("vendor",vendor);
        
    } catch (error) {
        console.error("Error fetching vendors:", error.response?.data || error.message);
        res.status(error.response?.status || 500).send({
            message: "Error fetching vendors",
            error: error.response?.data || error.message,
        });
    }
}

@Get('accounts')
async getAccounts(@Res() res: Response) {
    try {
        const token = await this.quickBookToken();
        if (!token) {
            return res.status(400).send("No token available for query");
        }

        const company_Id = process.env.COMPANY_ID;
        const response = await axios.get(
            `https://sandbox-quickbooks.api.intuit.com/v3/company/${company_Id}/query?query=SELECT * FROM Account`,
            {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Accept': 'application/json',
                },
            }
        );
        const data =response.data.QueryResponse.Account || []
        res.status(200).send(response.data.QueryResponse.Account || []);
        console.log(data);
        
    } catch (error) {
        console.error("Error fetching accounts:", error.response?.data || error.message);
        res.status(error.response?.status || 500).send({
            message: "Error fetching accounts",
            error: error.response?.data || error.message,
        });
    }
}

@Post('bill/create')
async createBill(@Body() billData: any, @Res() res: Response) {
    try {
        const token = await this.quickBookToken();
        if (!token) {
            return res.status(400).send("No token available for query");
        }

        const company_Id = process.env.COMPANY_ID;
        if (!company_Id) {
            return res.status(400).send("Company ID is missing or not configured");
        }

        const response = await axios.post(
            `https://sandbox-quickbooks.api.intuit.com/v3/company/${company_Id}/bill?minorversion=75`,
            billData,
            {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json',
                    Accept: 'application/json',
                },
            }
        );

        res.status(200).send(response.data);
    } catch (error) {
        console.error("QuickBooks API Creating Bill:", error.response?.data || error.message);
        res.status(error.response?.status || 500).send({
            message: "Error in Creating Bill",
            error: error.response?.data || error.message,
        });
    }
}

@Post('bill/delete')
async deleteBill(@Body() billData: any, @Res() res: Response) {
    try {
        const token = await this.quickBookToken();
        if (!token) {
            return res.status(400).send("No token available for query");
        }

        const company_Id = process.env.COMPANY_ID;
        if (!company_Id) {
            return res.status(400).send("Company ID is missing or not configured");
        }

        const response = await axios.post(
            `https://sandbox-quickbooks.api.intuit.com/v3/company/${company_Id}/bill?operation=delete&minorversion=75`,
            billData,
            {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json',
                    Accept: 'application/json',
                },
            }
        );

        res.status(200).send(response.data);
    } catch (error) {
        console.error("QuickBooks API Deleting Bill:", error.response?.data || error.message);
        res.status(error.response?.status || 500).send({
            message: "Error in Deleting Bill",
            error: error.response?.data || error.message,
        });
    }
}
@Post('bill/getQuery')
async getbillQuery(@Res() res:Response){
    try{
        const token = await this.quickBookToken();
        if (!token) {
            return res.status(400).send("No token available for query");
        }

        const company_Id = process.env.COMPANY_ID;
        if (!company_Id) {
            return res.status(400).send("Company ID is missing or not configured");
        }

        const response = await axios.get(
            `https://sandbox-quickbooks.api.intuit.com/v3/company/${company_Id}/query?query=select * from bill maxresults 2`,
            {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json',
                    Accept: 'application/json',
                },
            }
        );

        res.status(200).send(response.data.QueryResponse.Bill);
    } catch (error) {
        console.error("QuickBooks API Read Error:", error.response?.data || error.message);
        res.status(error.response?.status || 500).send({
            message: "Error in Reading QuickBooks",
            error: error.response?.data || error.message,
        });
    }

}  

@Post('bill/get/:id')
async getbill(@Param('id') id:string ,@Req() req:Request,@Res() res:Response){
    try{
        const token = await this.quickBookToken();
        if (!token) {
            return res.status(400).send("No token available for query");
        }

        const company_Id = process.env.COMPANY_ID;
        if (!company_Id) {
            return res.status(400).send("Company ID is missing or not configured");
        }

        const response = await axios.get(
            `https://sandbox-quickbooks.api.intuit.com/v3/company/${company_Id}/bill/${id}?minorversion=75`,
            {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json',
                    Accept: 'application/json',
                },
            }
        );

        res.status(200).send(response.data);
    } catch (error) {
        console.error("QuickBooks API Read Error:", error.response?.data || error.message);
        res.status(error.response?.status || 500).send({
            message: "Error in Reading QuickBooks",
            error: error.response?.data || error.message,
        });
    }

}

@Post('bill/update')
async updateBill(@Body() billData: any, @Res() res: Response) {
    try {
        const token = await this.quickBookToken();
        if (!token) {
            return res.status(400).send("No token available for query");
        }

        const company_Id = process.env.COMPANY_ID;
        if (!company_Id) {
            return res.status(400).send("Company ID is missing or not configured");
        }

        const response = await axios.post(
            `https://sandbox-quickbooks.api.intuit.com/v3/company/${company_Id}/bill?minorversion=75`,
            billData,
            {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json',
                    Accept: 'application/json',
                },
            }
        );

        res.status(200).send(response.data);
    } catch (error) {
        console.error("QuickBooks API Updating Bill:", error.response?.data || error.message);
        res.status(error.response?.status || 500).send({
            message: "Error in Updating Bill",
            error: error.response?.data || error.message,
        });
    }
}

/////////////CUSTOMER////////////


@Post('customer/create')
async createCustomer(@Body() customerData: any, @Res() res: Response) {
    try {
        const token = await this.quickBookToken();
        if (!token) {
            return res.status(400).send("No token available for query");
        }

        const company_Id = process.env.COMPANY_ID;
        if (!company_Id) {
            return res.status(400).send("Company ID is missing or not configured");
        }

        const response = await axios.post(
            `https://sandbox-quickbooks.api.intuit.com/v3/company/${company_Id}/customer?minorversion=75`,
            customerData,
            {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json',
                    Accept: 'application/json',
                },
            }
        );

        res.status(200).send(response.data);
    } catch (error) {
        console.error("QuickBooks API Creating Customer:", error.response?.data || error.message);
        res.status(error.response?.status || 500).send({
            message: "Error in Creating Customer",
            error: error.response?.data || error.message,
        });
    }

}

@Get('customer/getQuery')
async queryCustomer(@Req() req: Request, @Res() res: Response) {
    try {
        const token = await this.quickBookToken();
        if (!token) {
            return res.status(400).send("No token available for query");
        }

        const company_Id = process.env.COMPANY_ID;
        if (!company_Id) {
            return res.status(400).send("Company ID is missing or not configured");
        }

       
        

        const response = await axios.get(
            `https://sandbox-quickbooks.api.intuit.com/v3/company/${company_Id}/query?query=select * from Customer Where Metadata.LastUpdatedTime > '2025-03-24'`,
            {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json',
                    Accept: 'application/json',
                },
            }
        );

        res.status(200).send(response.data.QueryResponse.Customer);
    } catch (error) {
        console.error("QuickBooks API Query Error:", error.response?.data || error.message);
        res.status(error.response?.status || 500).send({
            message: "Error in querying QuickBooks",
            error: error.response?.data || error.message,
        });
    }
}


@Post('customer/get/:id')
async getCustomer(@Param('id') id:string ,@Req() req:Request,@Res() res:Response){
    try{
        const token = await this.quickBookToken();
        if (!token) {
            return res.status(400).send("No token available for query");
        }

        const company_Id = process.env.COMPANY_ID;
        if (!company_Id) {
            return res.status(400).send("Company ID is missing or not configured");
        }

        const response = await axios.get(
            `https://sandbox-quickbooks.api.intuit.com/v3/company/${company_Id}/customer/${id}?minorversion=75`,
            {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json',
                    Accept: 'application/json',
                },
            }
        );

        res.status(200).send(response.data);
    } catch (error) {
        console.error("QuickBooks API Read Error:", error.response?.data || error.message);
        res.status(error.response?.status || 500).send({
            message: "Error in Reading QuickBooks",
            error: error.response?.data || error.message,
        });
    }

}



@Post('customer/update')
async getUpdate(@Body() data:any,@Req() req:Request,@Res() res:Response){
    try{
        const token = await this.quickBookToken();
        if (!token) {
            return res.status(400).send("No token available for query");
        }

        const company_Id = process.env.COMPANY_ID;
        if (!company_Id) {
            return res.status(400).send("Company ID is missing or not configured");
        }

        const response = await axios.post(
            `https://sandbox-quickbooks.api.intuit.com/v3/company/${company_Id}/customer?minorversion=75`,data,
            {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json',
                    Accept: 'application/json',
                },
            }
        );

        res.status(200).send(response.data);
    } catch (error) {
        console.error("QuickBooks API Updating Error:", error.response?.data || error.message);
        res.status(error.response?.status || 500).send({
            message: "Error in Updating QuickBooks",
            error: error.response?.data || error.message,
        });
    }

}


@Post('customer/sparse_update')
async sparseUpdate(@Body() data:any,@Req() req:Request,@Res() res:Response){
    try{
        const token = await this.quickBookToken();
        if (!token) {
            return res.status(400).send("No token available for query");
        }

        const company_Id = process.env.COMPANY_ID;
        if (!company_Id) {
            return res.status(400).send("Company ID is missing or not configured");
        }

        const response = await axios.post(
            `https://sandbox-quickbooks.api.intuit.com/v3/company/${company_Id}/customer?minorversion=75`,data,
            {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json',
                    Accept: 'application/json',
                },
            }
        );

        res.status(200).send(response.data);
    } catch (error) {
        console.error("QuickBooks API Sparse Updating Error:", error.response?.data || error.message);
        res.status(error.response?.status || 500).send({
            message: "Error in Sparse Updating QuickBooks",
            error: error.response?.data || error.message,
        });
    }

}

/////////////////EMPLOYEE/////////////////

@Post('employee/create')
async createEmployee(@Body() accountDetail:any, @Res() res:Response){
  try{
    const token=await this.quickBookToken();
    if(!token) 
      res.status(400).send("No token for create account")
    const company_Id=process.env.COMPANY_ID;
    console.log("Company_Id:",company_Id);
    console.log(accountDetail)
    if(!company_Id) 
      return res.status(400).send("Company id not valid and non config")
    const response=await axios.post(`https://sandbox-quickbooks.api.intuit.com/v3/company/${company_Id}/employee`, 
      accountDetail,
      {
      headers:{
        'Authorization':`Bearer ${token}`,
        'Content-Type':'application/json',
        Accept:'application/json',
      }
    }
  );
  res.status(200).send(response.data)
  }catch(error) {
   console.log(error);
    res.status(500).send("Internal Server Error")
  }
}



@Get('employee/getQuery')
async queryEmployee( @Req() req: Request, @Res() res: Response) {
    try {
        const token = await this.quickBookToken();
        if (!token) {
            return res.status(400).send("No token available for query");
        }

        const company_Id = process.env.COMPANY_ID;
        if (!company_Id) {
            return res.status(400).send("Company ID is missing or not configured");
        }

        const queryString = encodeURIComponent("select * from Employee where DisplayName = 'Veenoth Meuller'")

        const response = await axios.get(
            `https://sandbox-quickbooks.api.intuit.com/v3/company/${company_Id}/query?query=${queryString}`,
            {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json',
                    Accept: 'application/json',
                },
            }
        );

        res.status(200).send(response.data);
    } catch (error) {
        console.error("QuickBooks API Query Error:", error.response?.data || error.message);
        res.status(error.response?.status || 500).send({
            message: "Error in querying QuickBooks",
            error: error.response?.data || error.message,
        });
    }
}


@Post('employee/get/:id')
async getEmployee(@Param('id') id:string ,@Req() req:Request,@Res() res:Response){
    try{
        const token = await this.quickBookToken();
        if (!token) {
            return res.status(400).send("No token available for query");
        }

        const company_Id = process.env.COMPANY_ID;
        if (!company_Id) {
            return res.status(400).send("Company ID is missing or not configured");
        }

        const response = await axios.get(
            `https://sandbox-quickbooks.api.intuit.com/v3/company/${company_Id}/employee/${id}?minorversion=75`,
            {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json',
                    Accept: 'application/json',
                },
            }
        );

        res.status(200).send(response.data);
    } catch (error) {
        console.error("QuickBooks API Read Error:", error.response?.data || error.message);
        res.status(error.response?.status || 500).send({
            message: "Error in Reading QuickBooks",
            error: error.response?.data || error.message,
        });
    }

}
@Post('employee/update')
async updateEmployee(@Body() account:any,@Res() res:Response){
    try{
        const token = await this.quickBookToken();
        if (!token) {
            return res.status(400).send("No token available for query");
        }

        const company_Id = process.env.COMPANY_ID;
        if (!company_Id) {
            return res.status(400).send("Company ID is missing or not configured");
        }

        const response = await axios.post(
            `https://sandbox-quickbooks.api.intuit.com/v3/company/${company_Id}/employee?minorversion=75`,
            account,
            {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json',
                    Accept: 'application/json',
                },
            }
        );
        
        res.status(200).send(response.data);
    } catch (error) {
        console.error("QuickBooks API Upadating Error:", error.response?.data || error.message);
        res.status(error.response?.status || 500).send({
            message: "Error in Updating QuickBooks",
            error: error.response?.data || error.message,
        });
    }

}

///////////////////////ITEM///////////////////


@Get('category')
async getCategory(@Res() res: Response) {
    try {
        const token = await this.quickBookToken();
        if (!token) {
            return res.status(400).send("No token available for query");
        }

        const company_Id = process.env.COMPANY_ID;
        const response = await axios.get(
            `https://quickbooks.api.intuit.com/v3/company/${company_Id}/companyinfo/${company_Id}`,
            {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Accept': 'application/json',
                },
            }
        );
        const data =response.data.QueryResponse.Account || []
        res.status(200).send(response.data.QueryResponse.Account || []);
        console.log(data);
        
    } catch (error) {
        console.error("Error fetching accounts:", error.response?.data || error.message);
        res.status(error.response?.status || 500).send({
            message: "Error fetching accounts",
            error: error.response?.data || error.message,
        });
    }
}


@Post('create/item')
async createItem(@Body() itemDetail, @Res() res:Response){
    try{
        const token = await this.quickBookToken();
        const company_Id = process.env.COMPANY_ID;
        if (!token) {
            return res.status(401).send("No QuickBooks token available or it has expired.");
        }
        if (!company_Id) {
            return res.status(400).send("Smack ID is missing from environment variables.");
        }
        const response =await axios.post(
            `https://sandbox-quickbooks.api.intuit.com/v3/company/${company_Id}/item?minorversion=4`,
            itemDetail,{
                headers:{
                    Authorization:`Bearer ${token}`,
                    "Content-Type": "application/json"
                }
            }
        );
        return res.status(200).send(response.data);
    }catch(err){
        console.error("error",err);
        return res.status(err.response?.status || 500).send(err.response?.data || 'Internal server error');
    }
}


@Post('create/category')
    async createCategory(@Body() categoryDetail:any, @Res() res:Response){
        try{
            const token = await this.quickBookToken();
            const company_Id = process.env.COMPANY_ID;
            if (!token) {
                return res.status(401).send("No QuickBooks token available or it has expired.");
            }
            if (!company_Id) {
                return res.status(400).send("Smack ID is missing from environment variables.");
            }
            const response = await axios.post(
                `https://sandbox-quickbooks.api.intuit.com/v3/company/${company_Id}/item?minorversion=4`,
                categoryDetail,
                {
                    headers:{
                        Authorization:`Bearer ${token}`,
                        "Content-Type": "application/json"
                    }
                }
            );
            return res.status(200).send(response.data);
        }catch(err){
            console.error("error",err);
            return res.status(err.response?.status || 500).send(err.response?.data || 'Internal server error');
        }
    }

///////////////////INVOICE/////////////////////


@Post('invoice/create')
async createInvoice(@Body() customerData: any, @Res() res: Response) {
    try {
        const token = await this.quickBookToken();
        if (!token) {
            return res.status(400).send("No token available for query");
        }

        const company_Id = process.env.COMPANY_ID;
        if (!company_Id) {
            return res.status(400).send("Company ID is missing or not configured");
        }

        const response = await axios.post(
            `https://sandbox-quickbooks.api.intuit.com/v3/company/${company_Id}/invoice?minorversion=75`,
            customerData,
            {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json',
                    Accept: 'application/json',
                },
            }
        );

        res.status(200).send(response.data);
    } catch (error) {
        console.error("QuickBooks API Creating Customer:", error.response?.data || error.message);
        res.status(error.response?.status || 500).send({
            message: "Error in Creating Customer",
            error: error.response?.data || error.message,
        });
    }

}



@Post('invoice/delete')
async deleteInvoice(@Body() customerData: any, @Res() res: Response) {
    try {
        const token = await this.quickBookToken();
        if (!token) {
            return res.status(400).send("No token available for query");
        }

        const company_Id = process.env.COMPANY_ID;
        if (!company_Id) {
            return res.status(400).send("Company ID is missing or not configured");
        }

        const response = await axios.post(
            `https://sandbox-quickbooks.api.intuit.com/v3/company/${company_Id}/invoice?operation=delete&minorversion=75`,
            customerData,
            {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json',
                    Accept: 'application/json',
                },
            }
        );

        res.status(200).send(response.data);
    } catch (error) {
        console.error("QuickBooks API Creating Customer:", error.response?.data || error.message);
        res.status(error.response?.status || 500).send({
            message: "Error in Creating Customer",
            error: error.response?.data || error.message,
        });
    }

}

@Post('invoice/void')
async voidInvoice(@Body() customerData: any, @Res() res: Response) {
    try {
        const token = await this.quickBookToken();
        if (!token) {
            return res.status(400).send("No token available for query");
        }

        const company_Id = process.env.COMPANY_ID;
        if (!company_Id) {
            return res.status(400).send("Company ID is missing or not configured");
        }

        const response = await axios.post(
            `https://sandbox-quickbooks.api.intuit.com/v3/company/${company_Id}/invoice?operation=void&minorversion=75`,
            customerData,
            {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json',
                    Accept: 'application/json',
                },
            }
        );

        res.status(200).send(response.data);
    } catch (error) {
        console.error("QuickBooks API Creating Customer:", error.response?.data || error.message);
        res.status(error.response?.status || 500).send({
            message: "Error in Creating Customer",
            error: error.response?.data || error.message,
        });
    }

}


@Post('invoice/getPdf/:id')
async getPdfInvoice(@Param('id') id:string, @Res() res: Response) {
    try {
        const token = await this.quickBookToken();
        if (!token) {
            return res.status(400).send("No token available for query");
        }

        const company_Id = process.env.COMPANY_ID;
        if (!company_Id) {
            return res.status(400).send("Company ID is missing or not configured");
        }
        if(!id){
            console.log("id isn't getting");
        }
        const response = await axios.get(
            `https://sandbox-quickbooks.api.intuit.com/v3/company/${company_Id}/invoice/${id}`,
            {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/pdf',
                },
                responseType:"arraybuffer",
            }
        );

        res.status(200).send(response.data);
    } catch (error) {
        console.error("QuickBooks API Creating Customer:", error.response?.data || error.message);
        res.status(error.response?.status || 500).send({
            message: "Error in Creating Customer",
            error: error.response?.data || error.message,
        });
    }

}



@Post('invoice/getQuery')
async getQueryInvoice(@Res() res: Response) {
    try {
        const token = await this.quickBookToken();
        if (!token) {
            return res.status(400).send("No token available for query");
        }

        const company_Id = process.env.COMPANY_ID;
        if (!company_Id) {
            return res.status(400).send("Company ID is missing or not configured");
        }
        

        const queryString = encodeURIComponent("select * from Invoice where id = '153'")

        const response = await axios.get(
            `https://sandbox-quickbooks.api.intuit.com/v3/company/${company_Id}/query?query=${queryString}&minorversion=75`,

            {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/text',
                },
            }
        );

        res.status(200).send(response.data);
    } catch (error) {
        console.error("QuickBooks API Creating Customer:", error.response?.data || error.message);
        res.status(error.response?.status || 500).send({
            message: "Error in Creating Customer",
            error: error.response?.data || error.message,
        });
    }

}


@Post('invoice/getId/:id')
async getIdInvoice(@Param('id') id:string,@Res() res: Response) {
    try {
        const token = await this.quickBookToken();
        if (!token) {
            return res.status(400).send("No token available for query");
        }

        const company_Id = process.env.COMPANY_ID;
        if (!company_Id) {
            return res.status(400).send("Company ID is missing or not configured");
        }
        

        const response = await axios.get(
            `https://sandbox-quickbooks.api.intuit.com/v3/company/${company_Id}/invoice/${id}?minorversion=75`,

            {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/text',
                },
            }
        );

        res.status(200).send(response.data);
    } catch (error) {
        console.error("QuickBooks API Creating Customer:", error.response?.data || error.message);
        res.status(error.response?.status || 500).send({
            message: "Error in Creating Customer",
            error: error.response?.data || error.message,
        });
    }
}



@Post('invoice/sendInvoice/:id')
async sendInvoice(@Param('id') id:string,@Res() res: Response) {
    try {
        const token = await this.quickBookToken();
        if (!token) {
            return res.status(400).send("No token available for query");
        }

        const company_Id = process.env.COMPANY_ID;
        if (!company_Id) {
            return res.status(400).send("Company ID is missing or not configured");
        }
        
        const fetchEmail = await axios.get(
            `https://sandbox-quickbooks.api.intuit.com/v3/company/${company_Id}/invoice/${id}?minorversion=75`,
            

            {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json',
                },
            }
        );
        const gmail = fetchEmail.data.Invoice.BillEmail? fetchEmail.data.Invoice.BillEmail.Address : "No email found";
      
      console.log("Customer Email:", gmail);
      
     const email = encodeURIComponent(gmail);
     console.log(email);

        const response= await axios.post(
            `https://sandbox-quickbooks.api.intuit.com//v3/company/${company_Id}/invoice/${id}/send?sendTo=${email}&minorversion=75`,
            {},

            {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/octet-stream',
                },
            }
        );

        res.status(200).send(response.data);

    } catch (error) {
        console.error("QuickBooks API Creating Customer:", error.response?.data || error.message);
        res.status(error.response?.status || 500).send({
            message: "Error in Creating Customer",
            error: error.response?.data || error.message,
        });
    }
}


@Post('invoice/sparse_update')
async sparseiUpdate(@Body() data:any,@Req() req:Request,@Res() res:Response){
    try{
        const token = await this.quickBookToken();
        if (!token) {
            return res.status(400).send("No token available for query");
        }

        const company_Id = process.env.COMPANY_ID;
        if (!company_Id) {
            return res.status(400).send("Company ID is missing or not configured");
        }

        const response = await axios.post(
            `https://sandbox-quickbooks.api.intuit.com/v3/company/${company_Id}/invoice?minorversion=75`,data,
            {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json',
                    Accept: 'application/json',
                },
            }
        );

        res.status(200).send(response.data);
    } catch (error) {
        console.error("QuickBooks API Sparse Updating Error:", error.response?.data || error.message);
        res.status(error.response?.status || 500).send({
            message: "Error in Sparse Updating QuickBooks",
            error: error.response?.data || error.message,
        });
    }

}

@Post('invoice/update')
async updateInvoice(@Body() account:any,@Res() res:Response){
    try{
        const token = await this.quickBookToken();
        if (!token) {
            return res.status(400).send("No token available for query");
        }

        const company_Id = process.env.COMPANY_ID;
        if (!company_Id) {
            return res.status(400).send("Company ID is missing or not configured");
        }

        const response = await axios.post(
            `https://sandbox-quickbooks.api.intuit.com/v3/company/${company_Id}/invoice?minorversion=75`,
            account,
            {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json',
                    Accept: 'application/json',
                },
            }
        );
        
        res.status(200).send(response.data);
    } catch (error) {
        console.error("QuickBooks API Upadating Error:", error.response?.data || error.message);
        res.status(error.response?.status || 500).send({
            message: "Error in Updating QuickBooks",
            error: error.response?.data || error.message,
        });
    }

}
///////////////////////PAYMENT///////////////////////////

}