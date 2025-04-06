package com.example.RTE;

import java.awt.PageAttributes.MediaType;
import java.util.*;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import java.util.regex.*;

import org.apache.log4j.spi.LoggerFactory;
import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody;

import com.opencsv.CSVReader;
import com.opencsv.CSVWriter;
import java.util.Collections;
import java.util.Dictionary;

class Key {
    private String requestPath;
    private int usageCount;

    // Constructor to initialize the fields
    public Key(String first, int second) {
        this.requestPath = first;
        this.usageCount = second;
    }
    public String getRequestPath() {
        return requestPath;
    }

    public int getUsageCount() {
        return usageCount;
    }

    @Override
    public String toString() {
        return "Key{" +
                "requestPath='" + requestPath + '\'' +
                ", usageCount=" + usageCount +
                '}';
    }
}


@RestController
public class Rest1sService {
boolean flag = true;
List<String> journal_paper_5_services = Arrays.asList("ts-admin-order-service", "ts-avatar-service", "ts-news-service", "ts-ticket-office-service", "ts-voucher-service");
List<String> out_of_scope = Arrays.asList("ts-news-service", "ts-ticket-office-service", "ts-preserve-other-service" );
public String find_Min_and_Max_Vulnerability_values () throws IOException {
	System.out.println("------------------------------****find_Min_and_Max_Vulnerability_values-----------------------------------------------start");
	System.out.println("--------------------------------------------------------------------------------------------------------------------------------------------start");
	System.out.println("--------------------------------------------------------------------------------------------------------------------------------------------start");
	System.out.println("--------------------------------------------------------------------------------------------------------------------------------------------start");
	System.out.println("--------------------------------------------------------------------------------------------------------------------------------------------start");
	System.out.println("--------------------------------------------------------------------------------------------------------------------------------------------start");
	System.out.println("-----Falg======"+flag);

    URL u = null;
    URL uu = null;
    Double V_min = 0.0;
    Double V_max = 0.0;
    List<Double> list_min_max_v = new ArrayList<>();
    String returnList = "";


    List<String> list = null;

    Double V_value = 0.0;

    if (flag) {
        u = new URL("http://localhost:9708/getservicenames");
      	System.out.println("getAllServiceName() URL:"+u.toString());
   }
   else {
       u = new URL("http://stixservice:9708/getservicenames");
        System.out.println("getAllServiceName() URL:"+u.toString());
   }
   // Fo

    try (InputStream in = u.openStream()) {
    	 System.out.println(" ::::::::: In try :::::::::");

         InputStreamReader ins = new InputStreamReader(in);
         BufferedReader re = new BufferedReader(ins);
         StringBuilder json_obj = new StringBuilder();
         int c;
         while ((c = re.read()) != -1) {
         	json_obj.append((char) c);
         }
         System.out.println(">>>>>>>>>> json_obj() URL:"+json_obj.toString());

         list = Arrays.asList( json_obj.toString().split("\\s*,\\s*"));
	    System.out.println("list 11111====="+list);

         for (int i = 0 ; i < list.size(); i++) {

 	    		if (list.get(i).toString() != ""){
 	    			 String[] paths = list.get(i).toString().split("&");
 	   			     System.out.println("paths======:"+ paths);
 	   			     System.out.println("paths[0]======:"+ paths[0]);
 	   			     System.out.println("paths[1]======:"+ paths[1]);
 	   			 if (!out_of_scope.contains(paths[0])) {
 	   			 if (!paths[1].contains("nfs-subdir-external-provisioner")) {
 	   					
 	   			  if (!paths[1].contains("mongo")) {
  	   			     System.out.println("Image does not contains: mongo");
  	   			     	
		   			     if (!paths[1].contains("mysql") ) { 		    	//if (!journal_paper_5_services.contains(paths[0])) {
		  	   			     System.out.println("Image does not contains: mysql");

 	    	    	System.out.println("list.get(i).toString()======:"+ list.get(i).toString());


	    			     String vulneritydata = "";
	    			     if (flag) {
	    		            uu = new URL("http://localhost:9708/getVulnerabilityData?imagename="+ paths[1]);
	    		        }
	    		        else {
	    		            uu = new URL("http://stixservice:9708/getVulnerabilityData?imagename="+ paths[1]);

	    		        }
	    			     try (InputStream imn = uu.openStream()) {
	    			         InputStreamReader inss = new InputStreamReader(imn);
	    			         BufferedReader ree = new BufferedReader(inss);
	    			         StringBuilder json_objj = new StringBuilder();
	    			         int cc;
	    			         while ((cc = ree.read()) != -1) {
	    			        	 json_objj.append((char) cc);
	    			         }
	    			         vulneritydata = json_objj.toString();
	  	    			   System.out.println(" vulneritydata:"  + vulneritydata);

	    			     }
	    			  
	    			   String cricial = vulneritydata.split("CRITICAL\":\"")[1].split("\"")[0];
	    		        String high = vulneritydata.split("HIGH\":\"")[1].split("\"")[0];
	    		        String med = vulneritydata.split("MEDIUM\":\"")[1].split("\"")[0];
	    		        String low = vulneritydata.split("LOW\":\"")[1].split("\"")[0];

	    			   
	    			   V_value = (Double.valueOf(cricial) * 0.4) +  (Double.valueOf(high) * 0.3) + (Double.valueOf(med) * 0.2) + (Double.valueOf(low) * 0.1);
	    			   System.out.println(" >>>>>>>>>>>>>>>>>> V_value= "+V_value + " <<<<<<<<<<<<<<<<<<<<<<<<< For the service: " + paths[0]);
	    			   list_min_max_v.add(V_value);
	    				}
 	   			  }
 	   			 }
 	   			  //
 	   			 }
 	    		}


 	   		System.out.println("find_min_value:="+ find_min_value(list_min_max_v));
 	   		System.out.println("find_max_value:="+ find_max_value(list_min_max_v));
 	   	returnList = find_min_value(list_min_max_v) + "#" + find_max_value(list_min_max_v);



		System.out.println("------------------------------****find_Min_and_Max_Vulnerability_values-----------------------------------------------start");
		System.out.println("--------------------------------------------------------------------------------------------------------------------------------------------start");
		System.out.println("--------------------------------------------------------------------------------------------------------------------------------------------start");
		System.out.println("--------------------------------------------------------------------------------------------------------------------------------------------start");
		System.out.println("--------------------------------------------------------------------------------------------------------------------------------------------start");
         }

        return returnList;

    }
    catch  (Exception ex) {
		// TODO Auto-generated catch block
		ex.printStackTrace();

    }
	return returnList;
}

public static Double find_min_value(List<Double> list)
{
    if (list == null || list.size() == 0) {
        return Double.MAX_VALUE;
    }
    List<Double> sortthem = new ArrayList<>(list);
    Collections.sort(sortthem);
    return sortthem.get(0);
}

public static Double find_max_value(List<Double> list)
{
    if (list == null || list.size() == 0) {
        return Double.MIN_VALUE;
    }
    List<Double> sortthem = new ArrayList<>(list);
    Collections.sort(sortthem);

    // last element in the sorted list would be maximum
    return sortthem.get(sortthem.size() - 1);
}

// Call TIS > find V score for each > find TM intial values for all services
public List JournalPaperWork () throws IOException {


  	System.out.println("------------------------------****getAllServiceNameFromTISTemp-----------------------------------------------start");
  	File file= new File (""+"Metrics2.csv");
	FileWriter out_file;
    URL u = null;
    URL uu = null;
    Double V_value = 0.0;
    Double TM_initial = 0.0;
    String list_v_min_max_values = find_Min_and_Max_Vulnerability_values();

    String V_min = list_v_min_max_values.split("#")[0];
    String V_max = list_v_min_max_values.split("#")[1];

    // Find Min and Max Vulnerability score
   	System.out.println("@@@@@@@@@@@@@@@@@ list_v_min_max_values:"+ list_v_min_max_values);

   	System.out.println("@@@@@@@@@@@@@@@@@ V_min:"+ V_min);
   	System.out.println("@@@@@@@@@@@@@@@@@ V_max:"+ V_max);





    // Find TM score and set V value for each service, in this use the previous founded
    // Min and Max
    if (flag) {
        u = new URL("http://localhost:9708/getservicenames");
       	System.out.println("getAllServiceName() Local URL:"+u.toString());
    }
    else {
        u = new URL("http://stixservice:9708/getservicenames");

         System.out.println("getAllServiceName() URL:"+u.toString());
    }
    // For local environment testing purpose, use the below URL

    // For a production environment, call Prometheus directly to its default port 9090 to gather the sum of all istio_requests_total then
    List<String> list = null;
    try (InputStream in = u.openStream()) {
        System.out.println(" ::::::::: In try :::::::::");

        InputStreamReader ins = new InputStreamReader(in);
        BufferedReader re = new BufferedReader(ins);
        StringBuilder json_obj = new StringBuilder();
        int c;
        while ((c = re.read()) != -1) {
        	json_obj.append((char) c);
        }
        System.out.println("obj====json_obj.toString()"+ json_obj.toString());
        System.out.println("obj====json_obj.toString().getClass().getName()"+ json_obj.toString().getClass().getName());
        list = Arrays.asList( json_obj.toString().split("\\s*,\\s*"));
	    System.out.println("list 2222====="+list);


        System.out.println("obj====TYPE:::::"+ json_obj.getClass().getName());

	   	file.createNewFile();
	    out_file = new FileWriter(file);
	    CSVWriter writer = new CSVWriter(out_file);
	   	String[] header_ = { "Microservice_name", "AIS", "ADS", "ACS", "VV" , "TM", "CanAccess", "CRUDOperaions", "grpcAllRequestPathsANDUsages"};
	    writer.writeNext(header_);




	    for (int i = 0 ; i < list.size(); i++) {

	    	System.out.println("list.get(i).toString()======:"+ list.get(i).toString());
	    		if (list.get(i).toString() != "" ){
	    	    long start = System.currentTimeMillis();


	    		 String[] paths = list.get(i).toString().split("&");
   			     System.out.println("paths======:"+ paths);
   			     System.out.println("paths[0]======:"+ paths[0]);
   			     System.out.println("paths[1]======:"+ paths[1]);
   			     System.out.println("!paths[1].contains(\"mongo\")=====:"+ (!paths[1].contains("mongo")));
   			     System.out.println("!paths[1].contains(\"mysql\")=====:"+ (!paths[1].contains("mysql")));

   			     System.out.println("!paths[1].contains(\"mongo\") || !paths[1].contains(\"mysql\")=====:"+ (!paths[1].contains("mongo") || !paths[1].contains("mysql")));
   			     		
 	   			 if (!out_of_scope.contains(paths[0])) {
 	   				if (!paths[1].contains("nfs-subdir-external-provisioner")) {
	   			     if (!paths[1].contains("mongo")) {
	  	   			     System.out.println("Image does not contains: mongo");

		   			     if (!paths[1].contains("mysql") ) {
		  	   			     System.out.println("Image does not contains: mysql");

	    			// Rami if (journal_paper_5_services.contains(paths[0])) {

	    			     String vulneritydata = "";
	    			     if (flag) {
	    		             uu = new URL("http://localhost:9708/getVulnerabilityData?imagename="+ paths[1]);
	    		           	System.out.println("getVulnerabilityData() URL:"+u.toString());
	    		        }
	    		        else {
	    		             uu = new URL("http://stixservice:9708/getVulnerabilityData?imagename="+ paths[1]);

	    		             System.out.println("getAllServiceName() URL:"+u.toString());
	    		        }
	    			     try (InputStream imn = uu.openStream()) {
	    			         System.out.println(" ::::::::: In try :::::::::");

	    			         InputStreamReader inss = new InputStreamReader(imn);
	    			         BufferedReader ree = new BufferedReader(inss);
	    			         StringBuilder json_objj = new StringBuilder();
	    			         int cc;
	    			         while ((cc = ree.read()) != -1) {
	    			        	 json_objj.append((char) cc);
	    			         }
	    			         System.out.println("obj====json_objj.toString()"+ json_objj.toString());
	    			         vulneritydata = json_objj.toString();
	    			     }


	    			 // Do the intial calcation:
	    			  String cricial = vulneritydata.split("\"CRITICAL\":\"")[1].split("\"")[0];
	    			  String high = vulneritydata.split("\"HIGH\":\"")[1].split("\"")[0];
	    			  String med = vulneritydata.split("\"MEDIUM\":\"")[1].split("\"")[0];
	    			  String low = vulneritydata.split("\"LOW\":\"")[1].split("\"")[0];
  
	    			     
	    			     
	    		        System.out.println(" ::::::::: In try cricial= :::::::::"+cricial);
  			         System.out.println(" ::::::::: In try high= :::::::::"+high);
  			         System.out.println(" ::::::::: In try med= :::::::::"+med);
  			         System.out.println(" ::::::::: In try low= :::::::::"+low);


  			       V_value = (Double.valueOf(cricial) * 0.4) +  (Double.valueOf(high) * 0.3) + (Double.valueOf(med) * 0.2) + (Double.valueOf(low) * 0.1);
			         System.out.println(" >>>>>>>>>>>>>>>>>> Double.valueOf(V_value)= "+Double.valueOf(V_value) + " <<<<<<<<<<<<<<<<<<<<<<<<<");
			         System.out.println(" >>>>>>>>>>>>>>>>>> Double.valueOf(V_min))= "+Double.valueOf(V_min) + " <<<<<<<<<<<<<<<<<<<<<<<<<");
			         System.out.println(" >>>>>>>>>>>>>>>>>> Double.valueOf(V_max)= "+Double.valueOf(V_max) + " <<<<<<<<<<<<<<<<<<<<<<<<<");
			         System.out.println(" >>>>>>>>>>>>>>>>>> (Double.valueOf(V_value)-Double.valueOf(V_min))= "+(Double.valueOf(V_value)-Double.valueOf(V_min)) + " <<<<<<<<<<<<<<<<<<<<<<<<<");
			         System.out.println(" >>>>>>>>>>>>>>>>>> (Double.valueOf(V_max)- Double.valueOf(V_min))= "+ (Double.valueOf(V_max)- Double.valueOf(V_min)) + " <<<<<<<<<<<<<<<<<<<<<<<<<");
			         System.out.println(" >>>>>>>>>>>>>>>>>> (Double.valueOf(V_value)-Double.valueOf(V_min))= "+(Double.valueOf(V_value)-Double.valueOf(V_min)) + " <<<<<<<<<<<<<<<<<<<<<<<<<");
			         if ((Double.valueOf(V_max)- Double.valueOf(V_min)) == 0) {
			        	 
			        	 // Divide by zero, then put 0.0
				         TM_initial = 100.00 -  (0.00 * 100.00);
			         }
			         else {
				         TM_initial = 100 -  (Double.valueOf(V_value)-Double.valueOf(V_min)) / (Double.valueOf(V_max)- Double.valueOf(V_min)) * 100;

			         }
			        		 // {TM}_{Initial}=100-\frac{(V_{value}\ -\ {Min}_{V_{value})}}{({Max}_{V_{value}}-{Min}_{V_{value}\ })}\times100
			         System.out.println(" >>>>>>>>>>>>>>>>>> TM_initial= "+TM_initial + " <<<<<<<<<<<<<<<<<<<<<<<<<");

			 	     System.out.println("[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]]]]]] (Start) <<<<<<<<< performance measurement for image scanning for image:"+ paths[0] );

	    			 String[] tem_data = { paths[0] , "", "" , "" ,  String.format("%.2f", V_value) , String.format("%.2f", TM_initial) , "",  "","", "" };
	    			 writer.writeNext(tem_data);
	    			 long end = System.currentTimeMillis();
		 	        System.out.println("[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]]]]]] (END) <<<<<<<<< performance measurement for image scanning for image:"+ paths[0] );
		 	          float result = (end - start) / 1000F;
			        	System.out.println("[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]]]]]] (RESULT) <<<<<<<<< performance measurement for image scanning for image:"+ result);

	    		    							}
	   			     }
	   			     
	   			     
	   			     //
 	   			 }
 	   			 }


	    		}


	    		}

	    writer.close();


        return list;
    }
    catch  (Exception ex) {
		// TODO Auto-generated catch block
		ex.printStackTrace();

    }
	return list;
}

public static String[] loadMicroserviceDataWithMSname(String MS) throws IOException {
    // BufferedReader to read the CSV file
    try (BufferedReader reader = new BufferedReader(new FileReader("Metrics2.csv"))) {
        String line;
        System.out.println("==== Loading Microservice Data ====");

        // Skip the header line
        reader.readLine();

        // Read each line and search for the matching microservice
        while ((line = reader.readLine()) != null) {
            String[] values = line.split(",", -1); // -1 to handle empty values correctly

            if (values.length < 6) {
                System.out.println("Skipping invalid line: " + line);
                continue;
            }

            String microserviceName = values[0].trim();
            System.out.println("==== microserviceName========"+ microserviceName );

            String vv = values[4].trim(); // Assuming TM is in column 5 (index 4)
            String tm = values[5].trim(); // Assuming VV is in column 6 (index 5)
            System.out.println("==== TM========"+ tm );
            System.out.println("==== VV========"+ vv );


            if (microserviceName.equalsIgnoreCase(MS)) {
                // Return TM and VV separately as an array
                return new String[] { tm.isEmpty() ? "0.0" : tm, vv.isEmpty() ? "0.0" : vv };
            }
        }
    }

    // Return null if the microservice was not found
    return null;
}


public static Map<String, List<String>> loadMicroserviceData() throws IOException {
    Map<String, List<String>> microserviceData = new HashMap<>();
    
    // BufferedReader to read the CSV file
    BufferedReader reader = new BufferedReader(new FileReader("Metrics2.csv"));
    String line;
    System.out.println("INNNNNNNNNNNNNNNNNNNNNN loadMicroserviceData() INNNNNNNNNNNNNNNNNNNNNN");
    System.out.println("INNNNNNNNNNNNNNNNNNNNNN loadMicroserviceData() INNNNNNNNNNNNNNNNNNNNNN");

    
    // Skip the header line
    reader.readLine();

    // Read each line and store data for each microservice
    while ((line = reader.readLine()) != null) {
        String[] values = line.split(",");
        String microserviceName = values[0];
        String tm = values[5];  // "TM" is in the 5th column (index 4)
        String vul = values[4]; // "VV" is in the 6th column (index 5)
        
        // Store the TM and VV values in a list
        List<String> tmVulValues = new ArrayList<>();
        tmVulValues.add("TM: " + tm);
        tmVulValues.add("VV: " + vul);
        
        // Add the microservice data to the map
        System.out.println("INNNNNNN microserviceName="+microserviceName);
        System.out.println("INNNNNNN tm="+tm);
        System.out.println("INNNNNNN vul="+vul);

        microserviceData.put(microserviceName, tmVulValues);
    }
    
    reader.close();
    
    return microserviceData;
}



// This function helps to get all service name.
public List getAllServiceName () throws IOException {
  	System.out.println("------------------------------****getAllServiceName-----------------------------------------------start");

    List list = new ArrayList();
    URL u = null;
    if (flag) {
    	
         u = new URL("http://localhost:9090/api/v1/query?query=group%20by%20(workload)%20(label_replace(istio_requests_total{namespace=%22default%22},%20%22workload%22,%20%22$1%22,%20%22source_workload%22,%20%22(.*)%22)%20or%20label_replace(istio_requests_total{namespace=%22default%22},%20%22workload%22,%20%22$1%22,%20%22destination_workload%22,%20%22(.*)%22))");
       	System.out.println("getAllServiceName() URL:"+u.toString());
    }
    else {
        u = new URL("http://prometheus:9090/api/v1/query?query=group%20by%20(workload)%20(label_replace(istio_requests_total{namespace=%22default%22},%20%22workload%22,%20%22$1%22,%20%22source_workload%22,%20%22(.*)%22)%20or%20label_replace(istio_requests_total{namespace=%22default%22},%20%22workload%22,%20%22$1%22,%20%22destination_workload%22,%20%22(.*)%22))");

       // u = new URL("http://prometheus:9090/api/v1/query?query=sum(istio_requests_total{run!=%22gw-nginx%22})%20by%20(app)");

         System.out.println("getAllServiceName() URL:"+u.toString());
    }
    // For local environment testing purpose, use the below URL

    // For a production environment, call Prometheus directly to its default port 9090 to gather the sum of all istio_requests_total then

    try (InputStream in = u.openStream()) {
        System.out.println(" ::::::::: In try :::::::::");

        InputStreamReader ins = new InputStreamReader(in);
        BufferedReader re = new BufferedReader(ins);
        StringBuilder json_obj = new StringBuilder();
        int c;
        while ((c = re.read()) != -1) {
        	json_obj.append((char) c);
        }
        JSONObject obj ;
    	obj = new JSONObject(json_obj.toString());
        System.out.println("obj===="+ obj.toString());

        if(obj.getString("status").trim().equalsIgnoreCase("success")) {
            System.out.println(" :::::::::status == success :::::::::");

	        JSONObject obj2 = new JSONObject(obj.get("data").toString());
            System.out.println(" :::::::::data= :::::::::"+  obj2.toString());

	        JSONArray obj3 = new JSONArray(obj2.get("result").toString());
            System.out.println(" :::::::::result= :::::::::"+  obj3.toString());

            for (int i =0 ; i < obj3.length(); i++ ) {
                System.out.println(" :::::::::in for loop :::::::::");

                JSONObject tem1 = new JSONObject(obj3.get(i).toString());
                System.out.println(" :::::::::tem1= :::::::::"+  tem1.toString());

                JSONObject temp2 = new JSONObject(tem1.get("metric").toString());
                System.out.println(" :::::::::metric= :::::::::"+  temp2.toString());
                System.out.println(" :::::::::metric length= :::::::::"+  temp2.length());

                if(temp2.length() == 0) {
                    System.out.println(" :::::::::NOOOO RUN= :::::::::");

                }
                else {
                	  list.add(temp2.get("workload".toString()));
                      System.out.println(" :::::::::run= :::::::::"+  temp2.get("workload".toString()));
                      System.out.println(" ----------------------------------------> "+  list.toString());


                }


            }
            System.out.println("end of for loop");

            //System.out.println(Arrays.toString(list.toArray()));

       }

        return list;
    }
}

public Map<String, List<Key>> getAllRequestPathsAndUsages () throws IOException {
	System.out.println("------------------------------getAllRequestPathsAndUsages-----------------------------------------------start");
    Map<String, List<Key>> requestPaht_and_usages = new HashMap<>();
    String gPRC_response_in_JSON = "";

 URL get_all_requests_paths = null;
 URL get_all_requests_paths_usages = null;

 
 if (flag) {
	 get_all_requests_paths = new URL("http://localhost:9090/api/v1/query?query=sum(istio_requests_total{request_protocol=%22grpc%22})%20by%20(request_path,destination_service_name)");
 }
 else {
	 get_all_requests_paths = new URL("http://prometheus:9090/api/v1/query?query=sum(istio_requests_total{request_protocol=%22grpc%22})%20by%20(request_path,destination_service_name)");

 }
 System.out.println("get_all_requests_paths:" +get_all_requests_paths);

 try (InputStream inn = get_all_requests_paths.openStream()) {
     InputStreamReader inss = new InputStreamReader(inn);
     BufferedReader e = new BufferedReader(inss);
     StringBuilder json_obj_gPRC = new StringBuilder();
     int c;
     while ((c = e.read()) != -1) {
     	json_obj_gPRC.append((char) c);
     }
 	gPRC_response_in_JSON = json_obj_gPRC.toString();
 	
	 System.out.println("get_all_requests_paths json_obj_gPRC:" +json_obj_gPRC);

     
}
catch(Exception e) {
}
 JSONObject obj;
 obj = new JSONObject(gPRC_response_in_JSON.toString());
	//final_JSON = final_JSON + ":::::::::::::::::::" + gPRC_response_in_JSON;
	if(obj.getString("status").trim().equalsIgnoreCase("success")) {
	        JSONObject obj2 = new JSONObject(obj.get("data").toString());
	        JSONArray obj3 = new JSONArray(obj2.get("result").toString());
	   //   System.out.println("obj3  JSONArray="+obj3.toString());
	      for (int i =0 ; i < obj3.length(); i++ ) {
	          JSONObject tem1 = new JSONObject(obj3.get(i).toString());
	          JSONObject temp2 = new JSONObject(tem1.get("metric").toString());
	          
	     	 //System.out.println("result:" +obj3);
	     	 //System.out.println("tem1:" +tem1);
	     	 System.out.println("request_path:" +temp2.get("request_path").toString());
	     	 System.out.println("destination_service_name:" +temp2.get("destination_service_name").toString());

	     	 if (flag) {
	     		 get_all_requests_paths_usages = new URL("http://localhost:9090/api/v1/query?query=count(count(istio_requests_total{request_path=%22"+temp2.get("request_path").toString()+"%22,%20source_principal!=\"unknown\"})%20by%20(source_principal))");

	     	 }
	     	 else {
	     		 get_all_requests_paths_usages = new URL("http://prometheus:9090/api/v1/query?query=count(count(istio_requests_total{request_path=%22"+temp2.get("request_path").toString()+"%22,%20source_principal!=\"unknown\"})%20by%20(source_principal))");

	     	 }
	     	 System.out.println(">>>>>>>>>>>>USAGES get_all_requests_paths_usages URL:" +get_all_requests_paths_usages.toString());

	     	 try (InputStream innn = get_all_requests_paths_usages.openStream()) {
	     	     InputStreamReader inss = new InputStreamReader(innn);
	     	     BufferedReader ee = new BufferedReader(inss);
	     	     StringBuilder json_obj_gPRC_e = new StringBuilder();
	     	     int c;
	     	     while ((c = ee.read()) != -1) {
	     	     	json_obj_gPRC_e.append((char) c);
	     	     }
	     	 	 JSONObject obj4;
		     	 System.out.println("json_obj_gPRC_e TTTTTT ====="+ json_obj_gPRC_e.toString());

	     	 	obj4 = new JSONObject(json_obj_gPRC_e.toString()); 
	     	 	if(obj4.getString("status").trim().equalsIgnoreCase("success")) {
	    	        JSONObject obj4_1 = new JSONObject(obj4.get("data").toString());
		   	     	 System.out.println(">>>>>>>>>>>>USAGES obj4_2 data:" +obj4_1.toString());

	    	        JSONArray obj4_2 = new JSONArray(obj4_1.get("result").toString());
	   	     	 System.out.println(">>>>>>>>>>>>USAGES obj4_2 result:" +obj4_2.toString());

		        JSONObject obj4_4 = new JSONObject(obj4_2.get(0).toString());
	   	     	 System.out.println(">>>>>>>>>>>>USAGES obj4_2.get(0):" +obj4_2.get(0).toString());

		        JSONArray obj5 = new JSONArray(obj4_4.get("value").toString());
	   	     	 System.out.println(">>>>>>>>>>>>USAGES obj4.get(\"value\"):" +obj5.toString());

		        int usages = Integer.parseInt(obj5.get(1).toString());


	 		     	 System.out.println("destination_service_name: "+temp2.get("destination_service_name").toString() +"   request_path:" +temp2.get("request_path").toString()+ " has usages="+ usages);

	 		        addKey(requestPaht_and_usages, temp2.get("destination_service_name").toString(), new Key(temp2.get("request_path").toString(), usages));


	 	   	     
	    	          
	    	    

	     	     
	     	}
	     	 }
	     	catch(Exception e) {
	     	}
	     	 
	          //destination_service_name_list = destination_service_name_list + temp2.get("destination_service_name").toString() + ",";
	      }
	}
	

	
 	



 return requestPaht_and_usages;
}

private static void addKey(Map<String, List<Key>> map, String keyString, Key key) {
    map.putIfAbsent(keyString, new ArrayList<>()); // Initialize list if key doesn't exist
    map.get(keyString).add(key); // Add the Key to the list
}

//This function helps to get all service-to-service CRUD/grpc operations.
public String getAllServiceCRUDOperations (String source, String DestList) throws IOException {
	System.out.println("------------------------------getAllService-to-service CRUD operaitons-----------------------------------------------start");

	// destination_principal source_principal
	// Rami: I did change the below from at the end " String SA = "spiffe://cluster.local/ns/default/sa/"
	// to this: spiffe://cluster.local/ns/default/sa/
 String SA = "spiffe://cluster.local/ns/default/sa/";
 URL get = null;
 URL post = null;
 URL check_if_it_is_REST_or_gRPC = null;
 URL delete = null;
 URL put = null;
 String ops =":";
 String final_return = "$";
 List final_list = new  ArrayList();
 String request_path = "";
 String IsitgRPC = "";

 String Dest_list []= DestList.split(",");
 for (int ii =0 ; ii < Dest_list.length; ii++ ) {
	 ops = ":";
	 List list = new ArrayList();
	 request_path = "";
	 IsitgRPC = "";

	 System.out.println("Dest service name:" +Dest_list[ii]);
	 if (flag) {

		 // Check if GET exist
		             //http://localhost:9090/api/v1/query?query=count(istio_requests_total{source_app=%22s0%22,%20destination_app=%22s10%22,%20request_method=%22GET%22,%20reporter=%22s0%22})%20by%20(app)
		 get = new URL("http://localhost:9090/api/v1/query?query=sum(istio_requests_total{source_principal=%22"+SA+source+"%22,destination_app!=%22unknown%22,destination_principal=%22"+SA+Dest_list[ii]+"%22,request_method=%22GET%22,reporter=%22source%22})%20by%20(destination_app)");
	 	 System.out.println("getAllServiceCRUDOperations() GET URL:"+get.toString());
		 // Check if POST exist
		 post = new URL("http://localhost:9090/api/v1/query?query=sum(istio_requests_total{source_principal=%22"+SA+source+"%22,destination_app!=%22unknown%22,destination_principal=%22"+SA+Dest_list[ii]+"%22,request_method=%22POST%22,destination_app!=%22unknown%22,reporter=%22source%22})%20by%20(destination_app)");
	 	 System.out.println("getAllServiceCRUDOperations() POST URL:"+post.toString());

	 	 // check if it is REST or gRPC
	 	 check_if_it_is_REST_or_gRPC = new URL("http://localhost:9090/api/v1/query?query=sum(istio_requests_total{source_principal=%22"+SA+source+"%22,destination_principal=%22"+SA+Dest_list[ii]+"%22,request_method=%22POST%22,destination_app!=%22unknown%22,reporter=%22source%22})%20by%20(destination_app,%20request_path,%20request_protocol)");
	 	 System.out.println("getAllServiceCRUDOperations() check_if_it_is_REST_or_gRPC URL:"+check_if_it_is_REST_or_gRPC.toString());



		 // Check if DELETE exist
		 delete = new URL("http://localhost:9090/api/v1/query?query=sum(istio_requests_total{source_principal=%22"+SA+source+"%22,destination_principal=%22"+SA+Dest_list[ii]+"%22,destination_app!=%22unknown%22,request_method=%22DELETE%22,reporter=%22source%22})%20by%20(destination_app)");
	 	 System.out.println("getAllServiceCRUDOperations() DELETE URL:"+delete.toString());

		 // Check if PUT exist
		 put = new URL("http://localhost:9090/api/v1/query?query=sum(istio_requests_total{source_principal=%22"+SA+source+"%22,destination_principal=%22"+SA+Dest_list[ii]+"%22,destination_app!=%22unknown%22,request_method=%22PUT%22,reporter=%22source%22})%20by%20(destination_app)");
	 	 System.out.println("getAllServiceCRUDOperations() PUT URL:"+put.toString());



	 }
	 else {
		 
		 
		 get = new URL("http://prometheus:9090/api/v1/query?query=sum(istio_requests_total{source_principal=%22"+SA+source+"%22,destination_app!=%22unknown%22,destination_principal=%22"+SA+Dest_list[ii]+"%22,request_method=%22GET%22,reporter=%22source%22})%20by%20(destination_app)");
	 	 System.out.println("getAllServiceCRUDOperations() GET URL:"+get.toString());
		 // Check if POST exist
		 post = new URL("http://prometheus:9090/api/v1/query?query=sum(istio_requests_total{source_principal=%22"+SA+source+"%22,destination_app!=%22unknown%22,destination_principal=%22"+SA+Dest_list[ii]+"%22,request_method=%22POST%22,destination_app!=%22unknown%22,reporter=%22source%22})%20by%20(destination_app)");
	 	 System.out.println("getAllServiceCRUDOperations() POST URL:"+post.toString());

	 	 // check if it is REST or gRPC
	 	 check_if_it_is_REST_or_gRPC = new URL("http://prometheus:9090/api/v1/query?query=sum(istio_requests_total{source_principal=%22"+SA+source+"%22,destination_principal=%22"+SA+Dest_list[ii]+"%22,request_method=%22POST%22,destination_app!=%22unknown%22,reporter=%22source%22})%20by%20(destination_app,%20request_path,%20request_protocol)");
	 	 System.out.println("getAllServiceCRUDOperations() check_if_it_is_REST_or_gRPC URL:"+check_if_it_is_REST_or_gRPC.toString());



		 // Check if DELETE exist
		 delete = new URL("http://prometheus:9090/api/v1/query?query=sum(istio_requests_total{source_principal=%22"+SA+source+"%22,destination_principal=%22"+SA+Dest_list[ii]+"%22,destination_app!=%22unknown%22,request_method=%22DELETE%22,reporter=%22source%22})%20by%20(destination_app)");
	 	 System.out.println("getAllServiceCRUDOperations() DELETE URL:"+delete.toString());

		 // Check if PUT exist
		 put = new URL("http://prometheus:9090/api/v1/query?query=sum(istio_requests_total{source_principal=%22"+SA+source+"%22,destination_principal=%22"+SA+Dest_list[ii]+"%22,destination_app!=%22unknown%22,request_method=%22PUT%22,reporter=%22source%22})%20by%20(destination_app)");
	 	 System.out.println("getAllServiceCRUDOperations() PUT URL:"+put.toString());

				// Check if GET exist
			     //http://localhost:9090/api/v1/query?query=count(istio_requests_total{source_app=%22s0%22,%20destination_app=%22s10%22,%20request_method=%22GET%22,%20reporter=%22s0%22})%20by%20(app)
			 // Check if GET exist
		     //http://localhost:9090/api/v1/query?query=count(istio_requests_total{source_app=%22s0%22,%20destination_app=%22s10%22,%20request_method=%22GET%22,%20reporter=%22s0%22})%20by%20(app) %20by%20(app)");
	




	 }
	 if (get != null) {
         System.out.println("GET it is not empty");
		 try (InputStream in = get.openStream()) {
	         System.out.println("GET in try");

		     InputStreamReader ins = new InputStreamReader(in);
		     BufferedReader re = new BufferedReader(ins);
		     StringBuilder json_obj = new StringBuilder();
		     int c;
		     while ((c = re.read()) != -1) {
		     	json_obj.append((char) c);
		     }
	         System.out.println("GET json_obj.toString="+json_obj.toString());

		     JSONObject obj ;
		 	obj = new JSONObject(json_obj.toString());
		     if(obj.getString("status").trim().equalsIgnoreCase("success")) {
			        JSONObject obj2 = new JSONObject(obj.get("data").toString());
			         System.out.println("GET obj2="+obj2.toString());

			        //System.out.println("getAllServiceCRUDOperations() obj2 get:"+obj2.toString());
			        JSONArray obj3 = new JSONArray(obj2.get("result").toString());
			         System.out.println("GET obj3="+obj3.toString());
		        	 System.out.println("GET obj3.length()="+obj3.length());

			         if (obj3.length() > 0) {
			        	 System.out.println("GET obj3 is not null");

			             //System.out.println("getAllServiceCRUDOperations() obj3 get:"+obj3.toString());

					        JSONObject obj4 = new JSONObject(obj3.get(0).toString());
					         System.out.println("GET obj4[0]="+obj4);

					         JSONObject temp2_2 = new JSONObject(obj4.get("metric").toString());
					         System.out.println("temp2_2="+ temp2_2.toString());

				            System.out.println("GET ops found for destination_app========"+temp2_2.get("destination_app").toString());
				            // obj5

				             if (temp2_2.get("destination_app").toString().equals(Dest_list[ii])) {
				            	 // Found the operation
						          System.out.println("Found the operation GET for servcie:"+temp2_2.get("destination_app").toString());
				            	 ops = ops + "GET";

				             }
			         }
			         else {
			        	 System.out.println("No proessing needed. GET is empty.");

			         }


		         }
		    }

		 }




	if (post != null) {
		System.out.println("post it is not empty");
	 try (InputStream in = post.openStream()) {
         System.out.println("POST in try");

         try (InputStream inn = check_if_it_is_REST_or_gRPC.openStream()) {
         // Check if it is grpc or REST
         if (check_if_it_is_REST_or_gRPC!= null ) {
    	     InputStreamReader ins_check_if_it_is_REST_or_gRPC = new InputStreamReader(inn);
    	     BufferedReader re_check_if_it_is_REST_or_gRPC = new BufferedReader(ins_check_if_it_is_REST_or_gRPC);
    	     StringBuilder json_obj_check_if_it_is_REST_or_gRPC = new StringBuilder();
    	     int c;
    	     while ((c = re_check_if_it_is_REST_or_gRPC.read()) != -1) {
    	    	 json_obj_check_if_it_is_REST_or_gRPC.append((char) c);
    	     }
             System.out.println("POST check_if_it_is_REST_or_gRPC="+json_obj_check_if_it_is_REST_or_gRPC.toString());

             JSONObject objj ;
             objj = new JSONObject(json_obj_check_if_it_is_REST_or_gRPC.toString());
             if(objj.getString("status").trim().equalsIgnoreCase("success")) {
 		        JSONObject obj2_check_if_it_is_REST_or_gRPC = new JSONObject(objj.get("data").toString());
		         System.out.println("check_if_it_is_REST_or_gRPC obj2="+obj2_check_if_it_is_REST_or_gRPC.toString());

 		      

 		        JSONArray obj3_check_if_it_is_REST_or_gRPC = new JSONArray(obj2_check_if_it_is_REST_or_gRPC.get("result").toString());
 		         System.out.println("obj3_check_if_it_is_REST_or_gRPC RESULT:"+obj3_check_if_it_is_REST_or_gRPC.toString());
 	        	 System.out.println("obj3_check_if_it_is_REST_or_gRPC.length()="+obj3_check_if_it_is_REST_or_gRPC.length());
 	        	 
 	 		        
 		         if (obj3_check_if_it_is_REST_or_gRPC.length() > 0) {
 		        	for (int i =0 ; i < obj3_check_if_it_is_REST_or_gRPC.length(); i++ ) {
 	 	 	          	       System.out.println("POST obj3 is not null");

				        JSONObject obj4__check_if_it_is_REST_or_gRPC = new JSONObject(obj3_check_if_it_is_REST_or_gRPC.get(i).toString());
				         System.out.println("obj4__check_if_it_is_REST_or_gRPC[i]="+obj4__check_if_it_is_REST_or_gRPC);

				         JSONObject temp2_2_check_if_it_is_REST_or_gRPC = new JSONObject(obj4__check_if_it_is_REST_or_gRPC.get("metric").toString());
				         System.out.println("temp2_2_check_if_it_is_REST_or_gRPC="+ temp2_2_check_if_it_is_REST_or_gRPC.toString());

			            System.out.println("POST ops found for request_protocol========"+temp2_2_check_if_it_is_REST_or_gRPC.get("request_protocol").toString());
			            // obj5

			             if (temp2_2_check_if_it_is_REST_or_gRPC.get("request_protocol").toString().equals("grpc")) {
			            	 IsitgRPC = "grpc";
			            	 // Found the operation
					          System.out.println("________________________________________________________________________________");
					          System.out.println("________________________________________________________________________________");
					          System.out.println("Dest. services:"+Dest_list);
					          String temp2 = "" + Arrays.toString(Dest_list);

					          System.out.println("Dest. services:"+temp2);

					          System.out.println("Source service name:"+source);
					          System.out.println("Dest. service name:"+Dest_list[ii]);
					          System.out.println("Request_path:"+temp2_2_check_if_it_is_REST_or_gRPC.get("request_path").toString());
					          
					          // oooo do for loop, if the requestPath found, ++1
					          // if not, then added it and put 1. 
					          // return the dic in the reutred method
					          System.out.println("________________________________________________________________________________");
					          System.out.println("________________________________________________________________________________");

					         request_path = request_path + "," + temp2_2_check_if_it_is_REST_or_gRPC.get("request_path").toString();

					       
					          }
					          else {

					        
			             }
 	 	 	          }
 		        	
 		         }
 		         else {
 		        	 System.out.println("No proessing needed. POST is empty.");

 		         }


 	         }

     	}
         	// if it is grpc, get all paths
         		// save the results in the file
         }


	     InputStreamReader ins = new InputStreamReader(in);
	     BufferedReader re = new BufferedReader(ins);
	     StringBuilder json_obj = new StringBuilder();
	     int c;
	     while ((c = re.read()) != -1) {
	     	json_obj.append((char) c);
	     }
         System.out.println("POST json_obj.toString="+json_obj.toString());

	     JSONObject obj ;
	 	obj = new JSONObject(json_obj.toString());
	     if(obj.getString("status").trim().equalsIgnoreCase("success")) {
		        JSONObject obj2 = new JSONObject(obj.get("data").toString());
		         System.out.println("POST obj2="+obj2.toString());

		        //System.out.println("getAllServiceCRUDOperations() obj2 get:"+obj2.toString());
		        JSONArray obj3 = new JSONArray(obj2.get("result").toString());
		         System.out.println("POST"+obj3.toString());
	        	 System.out.println("POST obj3.length()="+obj3.length());

		         if (obj3.length() > 0) {
		        	 System.out.println("POST obj3 is not null");

				        JSONObject obj4 = new JSONObject(obj3.get(0).toString());
				         System.out.println("POST obj4[0]="+obj4);

				         JSONObject temp2_2 = new JSONObject(obj4.get("metric").toString());
				         System.out.println("temp2_2="+ temp2_2.toString());

			            System.out.println("POST ops found for destination_app========"+temp2_2.get("destination_app").toString());
			            // obj5

			             if (temp2_2.get("destination_app").toString().equals(Dest_list[ii])) {
			            	 // Found the operation
					          System.out.println("Found the operation POST for servcie:"+temp2_2.get("destination_app").toString());
			            	 if (IsitgRPC == "grpc") {
			            		 System.out.println("Found service: \n" + temp2_2.get("destination_app").toString() + " the following paths: "+ request_path);
			            		 
			            		 ops = ops + "POST" + "[grpc~"+request_path;
			            	 }
			            	 else {

			            		 ops = ops + "POST";
			            	 }


			             }
		         }
		         else {
		        	 System.out.println("No proessing needed. POST is empty.");

		         }


	         }
	    }

	 }

	if (delete != null) {
		System.out.println("DELETE it is not empty");
		 try (InputStream in = delete.openStream()) {
	         System.out.println("DELETE in try");

		     InputStreamReader ins = new InputStreamReader(in);
		     BufferedReader re = new BufferedReader(ins);
		     StringBuilder json_obj = new StringBuilder();
		     int c;
		     while ((c = re.read()) != -1) {
		     	json_obj.append((char) c);
		     }
	         System.out.println("DELETE json_obj.toString="+json_obj.toString());

		     JSONObject obj ;
		 	obj = new JSONObject(json_obj.toString());
		     if(obj.getString("status").trim().equalsIgnoreCase("success")) {
			        JSONObject obj2 = new JSONObject(obj.get("data").toString());
			         System.out.println("DELETE obj2="+obj2.toString());

			        //System.out.println("getAllServiceCRUDOperations() obj2 get:"+obj2.toString());
			        JSONArray obj3 = new JSONArray(obj2.get("result").toString());
			         System.out.println("DELETE"+obj3.toString());
		        	 System.out.println("DELETE obj3.length()="+obj3.length());

			         if (obj3.length() > 0) {
			        	 System.out.println("DELETE obj3 is not null");

					        JSONObject obj4 = new JSONObject(obj3.get(0).toString());
					         System.out.println("DELETE obj4[0]="+obj4);

					         JSONObject temp2_2 = new JSONObject(obj4.get("metric").toString());
					         System.out.println("temp2_2="+ temp2_2.toString());

				            System.out.println("DELETE ops found for destination_app========"+temp2_2.get("destination_app").toString());
				            // obj5

				             if (temp2_2.get("destination_app").toString().equals(Dest_list[ii])) {
				            	 // Found the operation
						          System.out.println("Found the operation PUT for servcie:"+temp2_2.get("destination_app").toString());
				            	 ops = ops + "DELETE";

				             }

			         }
			         else {
			        	 System.out.println("No proessing needed. DELETE is empty.");

			         }

		         }
		    }

	}

	if (put != null) {

		System.out.println("PUT it is not empty");
		 try (InputStream in = put.openStream()) {
	         System.out.println("PUT in try");

		     InputStreamReader ins = new InputStreamReader(in);
		     BufferedReader re = new BufferedReader(ins);
		     StringBuilder json_obj = new StringBuilder();
		     int c;
		     while ((c = re.read()) != -1) {
		     	json_obj.append((char) c);
		     }
	         System.out.println("PUT json_obj.toString="+json_obj.toString());

		     JSONObject obj ;
		 	obj = new JSONObject(json_obj.toString());
		     if(obj.getString("status").trim().equalsIgnoreCase("success")) {
			        JSONObject obj2 = new JSONObject(obj.get("data").toString());
			         System.out.println("PUT obj2="+obj2.toString());

			        //System.out.println("getAllServiceCRUDOperations() obj2 get:"+obj2.toString());
			        JSONArray obj3 = new JSONArray(obj2.get("result").toString());
			         System.out.println("PUT"+obj3.toString());
		        	 System.out.println("PUT obj3.length()="+obj3.length());

			         if (obj3.length() > 0) {
			        	 System.out.println("PUT obj3 is not null");

			             //System.out.println("getAllServiceCRUDOperations() obj3 get:"+obj3.toString());

					        JSONObject obj4 = new JSONObject(obj3.get(0).toString());
					         System.out.println("PUT obj4[0]="+obj4);

					         JSONObject temp2_2 = new JSONObject(obj4.get("metric").toString());
					         System.out.println("temp2_2="+ temp2_2.toString());

				            System.out.println("PUT ops found for destination_app========"+temp2_2.get("destination_app").toString());
				            // obj5

				             if (temp2_2.get("destination_app").toString().equals(Dest_list[ii])) {
				            	 // Found the operation
						          System.out.println("Found the operation PUT for servcie:"+temp2_2.get("destination_app").toString());
				            	 ops = ops + "PUT";

				             }
			         }
			         else {
			        	 System.out.println("No proessing needed. PUT is empty.");

			         }


		         }
		    }
	}
	// s0=GET+POST+PUT+DELETE,s0=GET+POST+PUT+DELETE
	//list.add(Dest_list[ii]+ops);
	//final_list.add(list);
	
	final_return = final_return + Dest_list[ii]+ops + "@";
	System.out.println("getAllServiceCRUDOperations() list for source:"+ source +" towrd dest:"+ Dest_list[ii]+ list.toString() + " has:"+final_return);
 }





 return final_return;
}

// Read
public String FinAllPossiblePaths (String  servicename) throws IOException {
  	System.out.println("------------------------------FinAllPossiblePaths-----------------------------------------------start");
 // destination_principal source_principal
  	 String SA = "spiffe://cluster.local/ns/default/sa/";
  	 
  		int http_flag = 0;
		int gprc_flag = 0 ;
		String http_response_in_JSON = "";
		String gPRC_response_in_JSON = "";
	    String destination_service_name_list = "";

		Hashtable<String, String > dictAllPossiblePaths = new Hashtable<String, String >();

	// Test if this service use gPRC, if Yes: return the response as JSON for later process
	URL u_gprc = null;
	// prometheus:9090
	if (flag) {
		u_gprc = new URL ("http://localhost:9090/api/v1/query?query=count(istio_requests_total{destination_principal!=%22"+SA+servicename+"%22,app!=%22"+servicename+"%22,request_protocol=%22grpc%22})%20by%20(destination_service_name)");
       	System.out.println("FinAllPossiblePaths() gPRC URL:"+u_gprc.toString());
	}
	else {
		u_gprc = new URL ("http://prometheus:9090/api/v1/query?query=count(istio_requests_total{destination_principal!=%22"+SA+servicename+"%22,app!=%22"+servicename+"%22,request_protocol=%22grpc%22})%20by%20(destination_service_name)");
       	System.out.println("FinAllPossiblePaths() gPRC URL:"+u_gprc.toString());

	}
    // For local environment testing purpose, use the below URL to gather gRPC requests
	 //
    // For a production environment, call Prometheus directly to its default port 9090 to gather gPRCE requests and do the query.

	try (InputStream inn = u_gprc.openStream()) {
	        InputStreamReader inss = new InputStreamReader(inn);
	        BufferedReader e = new BufferedReader(inss);
	        StringBuilder json_obj_gPRC = new StringBuilder();
	        int c;
	        while ((c = e.read()) != -1) {
	        	json_obj_gPRC.append((char) c);
	        }

	        if (json_obj_gPRC.toString().length() > 70) {
	        	gprc_flag = 1;
	        	gPRC_response_in_JSON = json_obj_gPRC.toString();
	        }
	 }
	 catch(Exception e) {
	  }


	// For local environment testing purpose, use the below URL to gather HTTP requests
	//URL u_http = new URL ("http://localhost:8021/api/v1/query?query=istio_requests_total{destination_workload!=%22"+servicename+"%22,app=%22"+servicename+"%22,response_code=%22200%22,%20request_protocol=%22http%22}");
	URL u_http = null;

	if (flag) {
		// Final RAMI: 		 u_http = new URL ("http://localhost:9090/api/v1/query?query=count(istio_requests_total{destination_principal!=%22"+SA+servicename+"%22,app!=%22"+servicename+"%22,response_code=%22200%22,request_protocol=%22http%22})%20by%20(destination_service_name)");

		 u_http = new URL ("http://localhost:9090/api/v1/query?query=count(istio_requests_total{destination_principal!=%22"+SA+servicename+"%22,app!=%22"+servicename+"%22,request_protocol=%22http%22})%20by%20(destination_service_name)");
	     System.out.println("FinAllPossiblePaths() HTTP URL:"+u_http.toString());

	}
	else {
		 u_http = new URL ("http://prometheus:9090/api/v1/query?query=count(istio_requests_total{destination_principal!=%22"+SA+servicename+"%22,app!=%22"+servicename+"%22,request_protocol=%22http%22})%20by%20(destination_service_name)");

	     System.out.println("FinAllPossiblePaths() HTTP URL:"+u_http.toString());
	}
    // For a production environment, call Prometheus directly to its default port 9090 to gterh HTTP requests and do the query.
	 System.out.println(u_http);
	 try (InputStream innn = u_http.openStream()) {
	        InputStreamReader insss = new InputStreamReader(innn);
	        BufferedReader e = new BufferedReader(insss);
	        StringBuilder json_obje_HTTP = new StringBuilder();
	        int c;
	        while ((c = e.read()) != -1) {
	        	json_obje_HTTP.append((char) c);
	        }
	        if (json_obje_HTTP.toString().length() > 70) {
	        	http_flag = 1;
	        	http_response_in_JSON = json_obje_HTTP.toString();
	        }

	 }
	 catch(Exception e) {
	  }


	// Here if there is a gPRC request found, find all the destination service names to at the end get all possible paths for the giving service.
	if (gprc_flag == 1) {
	JSONObject obj ;
	obj = new JSONObject(gPRC_response_in_JSON.toString());
	//final_JSON = final_JSON + ":::::::::::::::::::" + gPRC_response_in_JSON;
	if(obj.getString("status").trim().equalsIgnoreCase("success")) {
	        JSONObject obj2 = new JSONObject(obj.get("data").toString());
	        JSONArray obj3 = new JSONArray(obj2.get("result").toString());
	   //   System.out.println("obj3  JSONArray="+obj3.toString());
	      for (int i =0 ; i < obj3.length(); i++ ) {
	          JSONObject tem1 = new JSONObject(obj3.get(i).toString());
	          JSONObject temp2 = new JSONObject(tem1.get("metric").toString());
	          destination_service_name_list = destination_service_name_list + temp2.get("destination_service_name").toString() + ",";
	      }
	}
	}
	// Here if there is a HTTP request found, find all the destination service names to at the end get all possible paths for the giving service.
	if (http_flag == 1) {
	JSONObject obj ;
	obj = new JSONObject(http_response_in_JSON.toString());
	   if(obj.getString("status").trim().equalsIgnoreCase("success")) {
	    	obj = new JSONObject(http_response_in_JSON.toString());
	      	System.out.println("-----------------------------------------------------------------------------");
		        JSONObject obj2 = new JSONObject(obj.get("data").toString());
		        JSONArray obj3 = new JSONArray(obj2.get("result").toString());
	          for (int i =0 ; i < obj3.length(); i++ ) {
	              JSONObject tem1 = new JSONObject(obj3.get(i).toString());
	              JSONObject temp2 = new JSONObject(tem1.get("metric").toString());
	          	  System.out.println("emp2.get(\"destination_service_name\").toString()====="+temp2.get("destination_service_name").toString());
		          destination_service_name_list = destination_service_name_list + temp2.get("destination_service_name").toString() + ",";
	          }
	   }


	}
	dictAllPossiblePaths.put( servicename, destination_service_name_list);
  	System.out.println("------------------------------Print before leaving:--------------------------------------------->>>>>"+ dictAllPossiblePaths.toString());

  	System.out.println("------------------------------FinAllPossiblePaths-----------------------------------------------end");
        return dictAllPossiblePaths.get(servicename);
}

// This function helps to get in-degree of a service (AIS as explained in the paper).
public String GetInDegree (String servicename) throws IOException {
  	System.out.println("------------------------------GetInDegree-----------------------------------------------start");
  	System.out.println("Source servicename="+ servicename);

 	 String SA = "spiffe://cluster.local/ns/default/sa/";

		int http_flag = 0; // 0 means such service does not use HTTP as a request protocol. Otherwide the service use HTTP as a request protocol.
		int gprc_flag = 0; // 0 means such service does not use gPRC as a request protocol. Otherwide service use gPRC as a request protocol.
		String http_response_in_JSON = "";
		String gPRC_response_in_JSON = "";
		int final_JSON = 0;
		int total_inDegree = 0;

		URL u_gprc = null;

		if (flag) {
			u_gprc = new URL ("http://localhost:9090/api/v1/query?query=count(count(istio_requests_total{destination_principal=%22"+SA+servicename+"%22,source_principal!=%22spiffe://cluster.local/ns/default/sa/bookinfo-gateway-istio%22,app!=%22"+servicename+"%22,grpc_response_status=%220%22,request_protocol=%22grpc%22})%20by%20(source_workload))");
			System.out.println("GetInDegree() gPRC URL:"+u_gprc.toString());

		}
		else {
			u_gprc = new URL ("http://prometheus:9090/api/v1/query?query=count(count(istio_requests_total{destination_principal=%22"+SA+servicename+"%22,source_principal!=%22spiffe://cluster.local/ns/default/sa/bookinfo-gateway-istio%22,app!=%22"+servicename+"%22,grpc_response_status=%220%22,request_protocol=%22grpc%22})%20by%20(source_workload))");

			System.out.println("CH- GetInDegree (): gPRC URL:"+u_gprc.toString());


		}
		// For local environment testing purpose, use the below URL to gather gPRC requests
		//u_gprc = new URL ("http://localhost:8021/api/v1/query?query=%20count(istio_requests_total{%20destination_service_name=%22"+servicename+"%22,%20app!=%22"+servicename+"%22,grpc_response_status=%220%22,request_protocol=%22grpc%22})");

	    // For a production environment, call Prometheus directly to its default port 9090 to gather gPRCE requests and do the query.
		System.out.println(u_gprc);
		try (InputStream inn = u_gprc.openStream()) {
		        InputStreamReader inss = new InputStreamReader(inn);
		        BufferedReader e = new BufferedReader(inss);
		        StringBuilder json_obj_gPRC = new StringBuilder();
		        int c;
		        while ((c = e.read()) != -1) {
		        	json_obj_gPRC.append((char) c);
		        }
		        if (json_obj_gPRC.toString().length() > 70) {
		        	gprc_flag = 1;
		        	gPRC_response_in_JSON = json_obj_gPRC.toString();
		        }

		 }
		 catch(Exception e) {
	      }

		// For local environment testing purpose, use the below URL to gather HTTP requests
		//URL u_http = new URL ("http://localhost:8021/api/v1/query?query=count(istio_requests_total{destination_service_name=%22"+servicename+"%22,%20app!=%22"+servicename+"%22,response_code=%22200%22,%20request_protocol=%22http%22})");
		URL u_http = null;
		if (flag) {
			// final RAmi 			u_http = new URL ("http://localhost:9090/api/v1/query?query=count(sum(istio_requests_total{destination_principal=%22"+SA+servicename+"%22,source_principal!=%22spiffe://cluster.local/ns/default/sa/bookinfo-gateway-istio%22,app!=%22"+servicename+"%22,app!=%22gw-nginx%22,response_code=%22200%22,request_protocol=%22http%22})%20by%20(source_workload))");

			u_http = new URL ("http://localhost:9090/api/v1/query?query=count(sum(istio_requests_total{destination_principal=%22"+SA+servicename+"%22,source_principal!=%22spiffe://cluster.local/ns/default/sa/bookinfo-gateway-istio%22,app!=%22"+servicename+"%22,app!=%22gw-nginx%22,request_protocol=%22http%22})%20by%20(source_workload))");
		    System.out.println("GetInDegree() HTTP URL:"+u_http.toString());
		}
		else {
			u_http = new URL ("http://prometheus:9090/api/v1/query?query=count(sum(istio_requests_total{destination_principal=%22"+SA+servicename+"%22,source_principal!=%22spiffe://cluster.local/ns/default/sa/bookinfo-gateway-istio%22,app!=%22"+servicename+"%22,app!=%22gw-nginx%22,request_protocol=%22http%22})%20by%20(source_workload))");
		    System.out.println("GetInDegree() HTTP URL:"+u_http.toString());
		}
	    // For a production environment, call Prometheus directly to its default port 9090 to gather gPRCE requests and do the query.
		System.out.println(u_http);
		try (InputStream innn = u_http.openStream()) {
		        InputStreamReader insss = new InputStreamReader(innn);
		        BufferedReader e = new BufferedReader(insss);
		        StringBuilder json_obje_HTTP = new StringBuilder();
		        int c;
		        while ((c = e.read()) != -1) {
		        	json_obje_HTTP.append((char) c);
		        }
		        if (json_obje_HTTP.toString().length() > 70) {
		        	http_flag = 1;
		        	http_response_in_JSON = json_obje_HTTP.toString();
		        }
		 }
		 catch(Exception e) {
	      }



	if (gprc_flag == 1) {
		JSONObject obj ;
    	obj = new JSONObject(gPRC_response_in_JSON.toString());
        if(obj.getString("status").trim().equalsIgnoreCase("success")) {
       	 	//System.out.println("gPRC_response used as a protcol for the service: " + servicename);
	        JSONObject obj2 = new JSONObject(obj.get("data").toString());
	        JSONArray obj3 = new JSONArray(obj2.get("result").toString());
	        JSONObject obj4 = new JSONObject(obj3.get(0).toString());
	        JSONArray obj5 = new JSONArray(obj4.get("value").toString());
	        total_inDegree =total_inDegree + Integer.parseInt(obj5.get(1).toString());
       }
	    }

	if (http_flag == 1) {

		JSONObject obj ;
    	obj = new JSONObject(http_response_in_JSON.toString());
        if(obj.getString("status").trim().equalsIgnoreCase("success")) {
	        JSONObject obj2 = new JSONObject(obj.get("data").toString());
	        JSONArray obj3 = new JSONArray(obj2.get("result").toString());
	        JSONObject obj4 = new JSONObject(obj3.get(0).toString());
	        JSONArray obj5 = new JSONArray(obj4.get("value").toString());
	        total_inDegree = total_inDegree + Integer.parseInt(obj5.get(1).toString());
       }
		System.out.println("------------------------------GetInDegree-----------------------------------------------end");

}
	return total_inDegree + "";
}
// This function helps to return the out-degree for a service (ADS) as explained in the paper.
public String GetOutDegree (String servicename) throws IOException {
	System.out.println("------------------------------GetOutDegree-----------------------------------------------start");
	System.out.println("Source servicename:" + servicename);

	 String SA = "spiffe://cluster.local/ns/default/sa/";

		int http_flag = 0; // 0 means such service does not use HTTP as a request protocol.
		int gprc_flag = 0; // 0 means such service does not use gPRC as a request protocol.
		String http_response_in_JSON = "";
		String gPRC_response_in_JSON = "";
		int final_JSON = 0;
		int total_outDegree = 0;
		URL u_gprc = null;


		// Test if this service use gPRC, if Yes: return the response as JSON for later process
		

		// For local environment testing purpose, use the below URL to gather gPRC requests
		//u_gprc = new URL ("http://localhost:8021/api/v1/query?query=count(istio_requests_total{destination_service_name!=%22"+servicename+"%22,source_app=%22"+servicename+"%22,app!=%22"+servicename+"%22,grpc_response_status=%220%22,request_protocol=%22grpc%22})");

	    // For a production environment, call Prometheus directly to its default port 9090 to gather gPRCE requests and do the query.
		if (flag) {
			u_gprc = new URL ("http://localhost:9090/api/v1/query?query=count(count(istio_requests_total{destination_principal!=%22"+SA+servicename+"%22,source_app=%22"+servicename+"%22,app!=%22"+servicename+"%22,grpc_response_status=%220%22,request_protocol=%22grpc%22})by(destination_principal))");
			System.out.println("GetOutDegree() u_gprc URL:"+u_gprc.toString());

		}
		else {
			u_gprc = new URL ("http://prometheus:9090/api/v1/query?query=count(count(istio_requests_total{destination_principal!=%22"+SA+servicename+"%22,source_app=%22"+servicename+"%22,app!=%22"+servicename+"%22,grpc_response_status=%220%22,request_protocol=%22grpc%22})by(destination_principal))");
			System.out.println("GetOutDegree() u_gprc URL:"+u_gprc.toString());

		}

		try (InputStream inn = u_gprc.openStream()) {
		        InputStreamReader inss = new InputStreamReader(inn);
		        BufferedReader e = new BufferedReader(inss);
		        StringBuilder json_obj_gPRC = new StringBuilder();
		        int c;
		        while ((c = e.read()) != -1) {
		        	json_obj_gPRC.append((char) c);
		        }
		        if (json_obj_gPRC.toString().length() > 70) {
		        	gprc_flag = 1;
		        	gPRC_response_in_JSON = json_obj_gPRC.toString();
		        }
		 }
		catch(Exception e) {
			 System.out.println("GetOutDegree() CATCH error: gprc URL does not works");

	      }
		System.out.println("CH- GetOutDegree (): u_gprc URL:"+u_gprc);



		// Test if this service use HTTP, if Yes: return the response as JSON for later process
		// For local environment testing purpose, use the below URL to gather HTTP requests
		 //URL u_http = new URL ("http://localhost:8021/api/v1/query?query=count(istio_requests_total{source_app=%22"+servicename+"%22,destination_service_name!=%22"+servicename+"%22,app!=%22"+servicename+"%22,response_code=%22200%22,request_protocol=%22http%22})");
		URL u_http = null;
		if (flag) {
			 u_http = new URL ("http://localhost:9090/api/v1/query?query=count(sum(istio_requests_total{source_principal=%22"+SA+servicename+"%22,destination_app!=%22unknown%22,destination_principal!=%22"+SA+servicename+"%22,app!=%22"+servicename+"%22,destination_app!=%22unknown%22,request_protocol=%22http%22})%20by%20(destination_principal))");
			 System.out.println("GetOutDegree() HTTP URL:"+u_http.toString());

		}
		else {
			 u_http = new URL ("http://prometheus:9090/api/v1/query?query=count(sum(istio_requests_total{source_principal=%22"+SA+servicename+"%22,destination_app!=%22unknown%22,destination_principal!=%22"+SA+servicename+"%22,app!=%22"+servicename+"%22,destination_app!=%22unknown%22,request_protocol=%22http%22})%20by%20(destination_principal))");

			 //u_http = new URL ("http://prometheus:9090/api/v1/query?query=count(istio_requests_total{source_app=%22"+servicename+"%22,destination_principal!=%22"+SA+servicename+"%22,app!=%22"+servicename+"%22,response_code=%22200%22,request_protocol=%22http%22})");
			 System.out.println("GetOutDegree() HTTP URL:"+u_http.toString());

		}
	    // For a production environment, call Prometheus directly to its default port 9090 to gather gPRCE requests and do the query.
		System.out.println("CH- GetOutDegree (): HTTP URL:"+u_http);


		 try (InputStream innn = u_http.openStream()) {
		        InputStreamReader insss = new InputStreamReader(innn);
		        BufferedReader ee = new BufferedReader(insss);
		        StringBuilder json_obje_HTTP = new StringBuilder();
		        int c;
		        while ((c = ee.read()) != -1) {
		        	json_obje_HTTP.append((char) c);
		        }

		        if (json_obje_HTTP.toString().length() > 70) {
		        	http_flag = 1;
		        	http_response_in_JSON = json_obje_HTTP.toString();
		        }
		 }
			catch(Exception e) {
	      }

	if (gprc_flag == 1) {
		JSONObject obj = new JSONObject(gPRC_response_in_JSON.toString());
        if(obj.getString("status").trim().equalsIgnoreCase("success")) {
	        JSONObject obj2 = new JSONObject(obj.get("data").toString());
	        JSONArray obj3 = new JSONArray(obj2.get("result").toString());
	        JSONObject obj4 = new JSONObject(obj3.get(0).toString());
	        JSONArray obj5 = new JSONArray(obj4.get("value").toString());
       	 total_outDegree =total_outDegree + Integer.parseInt(obj5.get(1).toString());
       }
	    }

	if (http_flag == 1) {

		JSONObject obj ;
    	obj = new JSONObject(http_response_in_JSON.toString());
        if(obj.getString("status").trim().equalsIgnoreCase("success")) {
	        JSONObject obj2 = new JSONObject(obj.get("data").toString());
	        JSONArray obj3 = new JSONArray(obj2.get("result").toString());
	        JSONObject obj4 = new JSONObject(obj3.get(0).toString());
	        JSONArray obj5 = new JSONArray(obj4.get("value").toString());
       	 total_outDegree = total_outDegree + Integer.parseInt(obj5.get(1).toString());
       }

}
	System.out.println("------------------------------GetOutDegree-----------------------------------------------end");

	return total_outDegree +"";
}

// This function helps to return the price that a malicious service has to pay.
public Double getPrice(String Microservice_name ) {

	// Price variable
	double price = 0.0;

	// Find at runtime the value of ACS_current for the giving Microservice_name at runtime
	double ACS_current = GetACS_current(Microservice_name);

	// Find at runtime the values of MinACS and MaxACS from all microservices
	List MinMax = minMaxACS();
	double ACSmin = 0.00;
	double ACSmax = 0.00;
	ACSmin = Double.valueOf(MinMax.get(0).toString());
	ACSmax = Double.valueOf(MinMax.get(1).toString());
	System.out.println("getPrice():::::: The ACSmin:"+ACSmin +" tand the ACSmax equals="+ACSmax);

	// Apply the rule of the organization
	if (ACS_current == ACSmax) {
		price= 0.9;
	}
	else if (ACSmin < ACS_current && ACS_current < ACSmax) {
		price= 0.5;
	}
	else if (ACS_current == ACSmin) {
		price= 0.2;
	}

	// Return the price
	return price;
}

// Return the current ACS value for the giving microservice name
public double GetACS_current(String Microservice_name ) {
	String strFile = "Metrics.csv";
    String[] nextRecord;
    double ACS_current = 0.0;
	 try {
	        CSVReader reader = new CSVReader(new FileReader(strFile));
	        while ((nextRecord = reader.readNext()) != null) {
	        	try {
		      	if (nextRecord[0].toString().equals(Microservice_name)) {
				        	ACS_current = Double.valueOf(nextRecord[3].toString());
			        	}
	        		}

	        	catch (Exception e) {
	        	}
	        }
	     }catch(IOException ie) {
	        ie.printStackTrace();
	     }
		return ACS_current;
}



@GetMapping("/SDG")
@ResponseBody
public StreamingResponseBody download() {
    File csv = new File("./Metrics.csv");

    StreamingResponseBody res = new StreamingResponseBody() {
        @Override
        public void writeTo(OutputStream outputStream) throws IOException {
            Files.copy(csv.toPath(), outputStream);
        }
    };

    // Return the StreamingResponseBody
    return res;
}

// This REST API is opens to allow the Istio sidecar to call it to find new trust value for a malicious service.

@RequestMapping("/DetermineNewTrustLevelforMaliciousMicroservice/{MaliciousMicroservice}/{TargetMicroservice}")
public Double DetermineNewTrustLevelforMaliciousMicroservice(@PathVariable(value = "MaliciousMicroservice") String MaliciousMicroservice,  @PathVariable(value = "TargetMicroservice") String TargetMicroservice ) {
	System.out.println("------------------------------DetermineNewTrustLevelforMaliciousMicroservice-----------------------------------------------start");

	double newTrustValue = 0.0;

	// Go get the price of the TargetMicroservice and return the priceToPay
	double priceToPay = getPrice(TargetMicroservice);
	System.out.println("DetermineNewTrustLevelforMaliciousMicroservice():::::: The price for:"+TargetMicroservice +" that has to pay equals="+priceToPay);

	// Go get the trust value (current) for the MaliciousMicroservice and return the currentTrustValue
	double currentTrustValue = GetTrustValue_current(MaliciousMicroservice);
	System.out.println("DetermineNewTrustLevelforMaliciousMicroservice()::::: The trsut value for:"+MaliciousMicroservice +" equals="+currentTrustValue);

	// Now, update the trust value for the MaliciousMicroservice to through decreasing currentTrustValue by the price: priceToPay*100. If the currentTrustValue == 0.0, no need to go negative. Just put 0.0
    int currentTrustValue_ = (int)currentTrustValue;
	if (currentTrustValue_ > 0) {
		newTrustValue = currentTrustValue - ((currentTrustValue) * (priceToPay));
		System.out.println("DetermineNewTrustLevelforMaliciousMicroservice()::::::The new trust value for:"+MaliciousMicroservice +" equals="+newTrustValue);
	}
	else {
		newTrustValue = 0.0;
	}

	// the below code will open the registry file  Metrics.txt to look for the Malicious service and replace it with the new trust value
	String strFile = "Metrics.csv";
	String[] nextRecord;
	double TrustValue_current = 0.0;
	 try {
	        CSVReader reader = new CSVReader(new FileReader(strFile));
	        // To know the row of the Malicious service to update the cell of the trust value
	        int rowLine = 0;
	        String temp = "";
		    String temp2 = "";
		    HashMap<Double, String> PreviousVictimsWithSpolight = new HashMap <Double, String> ();

	        while ((nextRecord = reader.readNext()) != null) {
	        	try {
	        	// If the service found, do the process to replace the trust value
		      	if (nextRecord[0].toString().equals(MaliciousMicroservice)) {
		      	 CSVReader reader2 = new CSVReader(new FileReader(strFile));
		         List<String[]> body = reader2.readAll();



		 	    body.get(rowLine)[4] = Double.toString(newTrustValue) ;

		 	    temp = temp + TargetMicroservice;
			    PreviousVictimsWithSpolight.put(newTrustValue, temp );



			    temp2 = body.get(rowLine)[5] + PreviousVictimsWithSpolight.toString();
		 	    body.get(rowLine)[5] = temp2 ;
		 	   URL stix = null;

		 	    if (flag) {
				 	    stix  = new URL ("http://localhost:9708/stix?trustscore="+Double.toString(newTrustValue)+"&maliciousservice="+MaliciousMicroservice+"&serviceNames="+temp+"&X509=YYSDJFSFJDSFDJFDSF"+newTrustValue);
						System.out.println("DetermineNewTrustLevelforMaliciousMicroservice() HTTP URL:"+stix.toString());
		 	    }
		 	    else {
			 	    stix  = new URL ("http://stixservice:9708/stix?trustscore="+Double.toString(newTrustValue)+"&maliciousservice="+MaliciousMicroservice+"&serviceNames="+temp+"&X509=YYSDJFSFJDSFDJFDSF"+newTrustValue);

						System.out.println("DetermineNewTrustLevelforMaliciousMicroservice() HTTP URL:"+stix.toString());
		 	    }
		 	    // Call the STIX generaiton service
		 	   System.out.println("Trying to call STIX");
	    		System.out.println(stix);

		 	   try (InputStream innn = stix.openStream()) {
			        InputStreamReader insss = new InputStreamReader(innn);
			        BufferedReader e = new BufferedReader(insss);
			        StringBuilder json_obje_HTTP = new StringBuilder();
			        int c;
			        while ((c = e.read()) != -1) {
			        	json_obje_HTTP.append((char) c);
			        }
			    		System.out.println("stixservice======="+json_obje_HTTP.toString());

			 }
			 catch(Exception e) {
			  }
		 	   System.out.println("Trying to call apg");

		 	  URL apg = null;
		 	  String option = "1";

		 	  if (flag) {
		 		   apg  = new URL ("http://localhost:9770/create?MS="+MaliciousMicroservice+"&TM="+Double.toString(newTrustValue));
		 		  // host.docker.internal
			 	  //  apg  = new URL ("http://host.docker.internal:9770/create?MS=\""+MaliciousMicroservice+"\"&TM="+Double.toString(newTrustValue));
					System.out.println("DetermineNewTrustLevelforMaliciousMicroservice() apg HTTP URL:"+apg.toString());
	 	    }
			    else {
			 		   apg  = new URL ("http://apg:9770/create?MS="+MaliciousMicroservice+"&TM="+Double.toString(newTrustValue));

					System.out.println("DetermineNewTrustLevelforMaliciousMicroservice() apg HTTP URL:"+apg.toString());
			    }



		 	   System.out.println("APG befroe try");

		 	   try (InputStream innn = apg.openStream()) {
			        InputStreamReader insss = new InputStreamReader(innn);
			        BufferedReader e = new BufferedReader(insss);
			        StringBuilder json_obje_HTTP = new StringBuilder();
				 	   System.out.println("APG in try");

			        int c;
			        while ((c = e.read()) != -1) {
			        	json_obje_HTTP.append((char) c);
			        }
			    		System.out.println("apg======="+json_obje_HTTP.toString());

			 }
			 catch(Exception e) {
			 	   System.out.println("APG in catch error:" + e.toString());
			  }
		 	   System.out.println("APG after try");

		 	     reader.close();
		 	     CSVWriter writer = new CSVWriter(new FileWriter(strFile));
		 	     writer.writeAll(body);
		 	     writer.flush();
		 	     writer.close();
			        	}
	        		}
	        	catch (Exception e) {
	        	}
	        	rowLine++;
	        }
	     }catch(IOException ie) {
	        ie.printStackTrace();
	     }
	    System.out.println("DetermineNewTrustLevelforMaliciousMicroservice() END of the method");
	return newTrustValue;
}

// This function helps to get the the current trust value in the registry
public double GetTrustValue_current(String Microservice_name ) {
	String strFile = "Metrics.csv";
	String[] nextRecord;
	double TrustValue_current = 0.0;
	 try {
	        CSVReader reader = new CSVReader(new FileReader(strFile));
	        while ((nextRecord = reader.readNext()) != null) {
	        	try {
		      	if (nextRecord[0].toString().equals(Microservice_name)) {
				        	TrustValue_current = Double.valueOf(nextRecord[4].toString());
			        	}
	        		}

	        	catch (Exception e) {
	        		System.out.println(e.getMessage());
	        	}
	        }
	     }catch(IOException ie) {
	        ie.printStackTrace();
	     }
	    System.out.println("GetTrustValue_current():::::: TrustValue_current="+TrustValue_current + " For MS:"+Microservice_name);
		return TrustValue_current;
}


// This function helps to find the min and max of ACS from all the microservices
public List minMaxACS () {
	String strFile = "Metrics.csv";
    String[] nextRecord;
    Double minACS = 1000000.0;
    Double maxACS = 0.0;
    Double temp = 0.0;

    List<String> minMax = new ArrayList<String>();

   minMax.add(minACS.toString());
   minMax.add(maxACS.toString());
	 try {
		 	// Read from the CSV all the ACS values then find the min and max among them.
	        CSVReader reader = new CSVReader(new FileReader(strFile));
	        while ((nextRecord = reader.readNext()) != null) {
	        	try {
	        			temp=Double.valueOf(nextRecord[3].toString());
	        			minACS=Double.valueOf(minMax.get(0));
	        			maxACS=Double.valueOf(minMax.get(1));
			        	if (temp > maxACS) {
			        		maxACS = temp;
			        		minMax.set(1,temp.toString());
			        	}
			        	if (temp < minACS) {
			        		minACS = temp;
			        		minMax.set(0,temp.toString());
			        	}
	        		}
	        	catch (Exception e) {
	        		System.out.println(e.getMessage());
	        	}
	        }
	     }catch(IOException ie) {
	        ie.printStackTrace();
	     }
		return minMax;
}


//  A REST API to allow me to test if RTE works or not in the cluster. You can remove it if you do not need it.

@RequestMapping("/test")
public String say() {
	System.out.println("Called test ---------------------------It is works");
	return "hi, it works!";
}



// A REST API to allow me to test if prometheus works or not in the cluster. You can remove it if you do not need it.
@RequestMapping("/checkprometheus")
public String checkprometheus() throws IOException {
	System.out.println("checkprometheus ::::::::::: checkprometheus::::::::::::::::::checkprometheus::::::::::::::::::: start");

	//URL u = new URL("http://localhost:8021/api/v1/query?query=sum(istio_requests_total)");
	URL u = null;
	if (flag) {
		 u = new URL("http://localhost:9090/api/v1/query?query=sum(istio_requests_total)");
	}
	else {
		 u = new URL("http://prometheus:9090/api/v1/query?query=sum(istio_requests_total)");

	}
    try (InputStream in = u.openStream()) {
        InputStreamReader ins = new InputStreamReader(in);
        BufferedReader re = new BufferedReader(ins);
        StringBuilder json_obj = new StringBuilder();
        int c;
        while ((c = re.read()) != -1) {

        	json_obj.append((char) c);
        }
        //System.out.println("Service JSON ="+json_obj.toString());
        JSONObject obj ;
    	obj = new JSONObject(json_obj.toString());
        return json_obj.toString();
    }
}




// This REST API helps istio sidecars outbound to check if the request from caller service to the target service is legit?
@RequestMapping("/IsItAnunauthorizedAccess/{MaliciousMicroservice}/{TargetMicroservice}")
public int IsItAnunauthorizedAccess(@PathVariable(value = "MaliciousMicroservice") String MaliciousMicroservice,  @PathVariable(value = "TargetMicroservice") String TargetMicroservice ) {
	 String Str = new String(TargetMicroservice);
	 System.out.println("IsItAnunauthorizedAccess():::::::::::: MaliciousMicroservice===="+ MaliciousMicroservice);
	 System.out.println("IsItAnunauthorizedAccess():::::::::::: TargetMicroservice===="+ TargetMicroservice);

     String temp [] = null;
    String[] nextRecord;
	String strFile = "Metrics.csv";
	List<String> Allservice = null;

	// This is the initial assumption that this access is not allow; otherwise set to true means it is safe
	int IsItAnunauthorizedAccess = 0; // not found: Malicious activity
	try {
	        CSVReader reader = new CSVReader(new FileReader(strFile));
	        while ((nextRecord = reader.readNext()) != null) {
	        	try {
	        		 System.out.println("IsItAnunauthorizedAccess():::::::::::: nextRecord[0].toString().equals(MaliciousMicroservice===="+ (nextRecord[0].toString().equals(MaliciousMicroservice)));

		      	if (nextRecord[0].toString().equals(MaliciousMicroservice)) {
				        	Allservice = new ArrayList<String>(Arrays.asList( nextRecord[7].split(",")));
			        		 System.out.println("IsItAnunauthorizedAccess():::::::::::: Allservice.size() > 0e===="+ (Allservice.size() > 0));
			        		 System.out.println("IsItAnunauthorizedAccess():::::::::::: Allservice===="+ Allservice);
			        		 
				        	if (Allservice.size() > 0) {
				        		for (int i=0 ;i <Allservice.size(); i ++) {
					        		 System.out.println("IsItAnunauthorizedAccess():::::::::::: Allservice.get(i).toString().equalsIgnoreCase(TargetMicroservice)> ===="+ (Allservice.get(i).toString().equalsIgnoreCase(TargetMicroservice)));
					        		 System.out.println("IsItAnunauthorizedAccess():::::::::::: Allservice.get(i).toLowerCase().contains(TargetMicroservice.toLowerCase()) ===="+ (Allservice.get(i).toLowerCase().contains(TargetMicroservice.toLowerCase())));
					        	        
					        	        // Use regex with word boundaries to ensure exact match
					        	        Pattern pattern = Pattern.compile("\\b" + Pattern.quote(TargetMicroservice.toLowerCase()) + "\\b", Pattern.CASE_INSENSITIVE);
					        	        Matcher matcher = pattern.matcher(Allservice.get(i).toLowerCase());
					        	        
					        	        if (matcher.find()) {
					        	            System.out.println("Exact word found!");
					        	        } else {
					        	            System.out.println("Word not found.");
					        	        }
				        			if (Allservice.get(i).toLowerCase().contains(TargetMicroservice.toLowerCase())) {
						        		 System.out.println("Allservice.get(i).toLowerCase().contains===="+ Allservice.get(i).toLowerCase());
						        		 System.out.println("TargetMicroservice.toLowerCase()===="+ TargetMicroservice.toLowerCase());

				        			    IsItAnunauthorizedAccess = 1; // found path. it is not a Malicious activity
				        			}

				        		}

				        	}
			        	}
	        		}

	        	catch (Exception e) {
	        		 System.out.println("IsItAnunauthorizedAccess():::::::::::: Exception e===="+ (e.getMessage().toString()));

	        		IsItAnunauthorizedAccess = 3; // error can not tell if it is Malicious activity or not
	        	}
	        }
	     }catch(IOException ie) {
    		 System.out.println("IsItAnunauthorizedAccess():::::::::::: Exception ie ===="+ (ie.getMessage().toString()));

	    	 IsItAnunauthorizedAccess = 3; // error can not tell if it is Malicious activity or not
	     }

	System.out.println("IsItAnunauthorizedAccess():::::::::::: IsItAnunauthorizedAccess="+IsItAnunauthorizedAccess);
	return IsItAnunauthorizedAccess;
}



// This REST API or as function can be called manually or by the RET after the timeframe as defined in the
@GetMapping(value="/ACS_baselinePhase")
public String ACS_baselinePhase () throws IOException {
	JournalPaperWork();
    
    


	System.out.println("---------------------- ACS_baselinePhase-------------------------- start");
	
	

	

	String in_degree_string = "";
	String out_degree_string = "";
	String ACS_string = "";
	String status = "";

	int out_degree = 0;
	int in_degree = 0;
	int ACS_in = 0;
		File file= new File (""+"Metrics.csv");
		FileWriter out_file;

	   if (file.exists()== false) {
			System.out.println("---------------------- File does not exists-------------------------- start");

		    status = "Metrics.csv file does not exists() >> creating the file with all ACS values for all microservice";
		   	file.createNewFile();
		    out_file = new FileWriter(file);
		    CSVWriter writer = new CSVWriter(out_file);
		   	String[] header_ = { "Microservice_name", "AIS", "ADS", "ACS", "TM", "Vul", "CanAccess", "CRUDOperaions" ,"grpcAllRequestPathsANDUsages" };
		    writer.writeNext(header_);

		    List list = getAllServiceName();
			System.out.println("----------------------list-------------------------- Stirng: "+ list.toString());
			System.out.println("----------------------list-------------------------- Length: "+ list.size());


		    for (int i = 0 ; i < list.size(); i++) {


			 out_degree_string = GetOutDegree(list.get(i).toString());
			 out_degree = Integer.parseInt(out_degree_string);
			 in_degree_string = GetInDegree(list.get(i).toString());
			 in_degree = Integer.parseInt(in_degree_string);
			 String destination_service_name_list  = FinAllPossiblePaths(list.get(i).toString());
             System.out.println("LAST TASK: list.get(i).toString()"+ list.get(i).toString());
             System.out.println("LAST TASK before: list.get(i).toString()"+ list.get(i).toString());
             System.out.println("LAST TASK before: list.get(i).toString().length"+ list.get(i).toString().length());

             String TM_ = "";
             String VV_ = "";
           

             try {
                 // Get the TM and VV values separately 
                 String[] result = loadMicroserviceDataWithMSname("\"" + list.get(i).toString() + "\"");
                 
                 if (result != null) {
                     // Print the TM and VV values separately
                     System.out.println("TM: " + result[0]);
                     System.out.println("VV: " + result[1]);
                     
                     TM_ = result[0].toString().replaceAll("\"", "");
                     VV_ = result[1].toString().replaceAll("\"", "");
                     
                 } else {
                     // Print a message if the microservice was not found
                     System.out.println("Microservice not found: " + list.get(i).toString());
                 }
             } catch (IOException e) {
                 System.err.println("Error reading the file: " + e.getMessage());
             }
             
			
			 ACS_in = out_degree * in_degree;
			 ACS_string = ACS_in + "";
				System.out.println("calling getAllRequestPathsAndUsages() from file creaiton.");

			String requestsPath_and_usages = "";
			List<Key> foundKeys = getAllRequestPathsAndUsages().get( list.get(i).toString());

		    // Check if the key exists and print the results
		    if (foundKeys != null) {
		        System.out.println("Found entries for shippingservice :");
		        for (Key key : foundKeys) {
		        	requestsPath_and_usages =  requestsPath_and_usages + key.getRequestPath().toString() +"/" + key.getUsageCount() + ",";
		        }
		    } else {
		        System.out.println("Key not found!");
		    }
		    System.out.println("requestsPath_and_usages==="+requestsPath_and_usages);
			 String[] tem_data = { list.get(i).toString() , in_degree_string, out_degree_string , ACS_string , TM_, VV_ , destination_service_name_list.toString(), getAllServiceCRUDOperations(list.get(i).toString(),destination_service_name_list).toString() , requestsPath_and_usages  };
			 requestsPath_and_usages = "";
			 writer.writeNext(tem_data);
		    									}
		     writer.close();
	   }
	   else {
		   status = "Metrics.csv file is exists(). This file can be called once after a specific defined time.";
	   }
		System.out.println("---------------------- ACS_baselinePhase-------------------------- end");

	return status;
}
}
