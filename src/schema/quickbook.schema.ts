import { Schema , Prop, SchemaFactory} from "@nestjs/mongoose";
@Schema({timestamps:true})

export class Credentials{
    @Prop()//,({require:any})
    clientId:String;
    @Prop()
    clientSecret:String;
    @Prop()
    accessToken:String;
    @Prop()
    refreshToken:String
    
    
}
export const credentialSchema= SchemaFactory.createForClass (Credentials)