package main

import (
	context "context"
	"flag"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/patrickmn/go-cache"
	_ "github.com/patrickmn/go-cache"
	"io/ioutil"
	securityv1beta1 "istio.io/api/security/v1beta1"
	v1beta1 "istio.io/api/type/v1beta1"
	v1beta3 "istio.io/client-go/pkg/apis/security/v1beta1"
	versionedclient "istio.io/client-go/pkg/clientset/versioned"
	apiv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	"k8s.io/client-go/util/retry"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var c = cache.New(90*time.Minute, 10*time.Minute)
var flag_ bool = true // True means in-cluster  // False means in IDE
var once sync.Once
var second sync.Once

type UsageEntry struct {
	MS_name   string
	gRPC_path string
}

func main() {
	startTime := time.Now()
	log.Println("APG Processing startTime:", startTime)

	//print("Return from main:", getConfigMap("M-L-L"))

	// Step 1: Obtain the metrics file from RTE which contains REST and/or gRPC microservice-to-microservice communications	get_metrics_from_RTE()
	get_metrics_from_RTE()

	// Step 2: create the baseline for both REST and gRPC protocols
	create_Cache_and_AP_Cases_1_2_3()
	endTime := time.Now() // End time
	processing_time := endTime.Sub(startTime)
	log.Println("APG Processing startTime:", startTime)
	log.Println("APG Processing endTime:", endTime)
	log.Println("APG Processing Time:", processing_time)

	router := gin.Default()

	// Step 3: APG gets ready to make adaptive AP on request from RTE
	// 	//http://localhost:9770/create?MS=teastore-webui&TM=90
	router.GET("/create", create)
	router.GET("/getcacheitem", getItemFromCache)
	router.Run(":9770")

}

// Return the K8s connection either in-cluster or in local env (such as from IDE)
func getConneciton(flag_ bool) *rest.Config {
	// True In cluster
	if flag_ {
		config_in_cluster, err := rest.InClusterConfig()
		if err != nil {
			panic(err.Error())
		}
		return config_in_cluster
		// False out of cluster
	} else {
		var kubeconfig *string
		flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
		if home := homedir.HomeDir(); home != "" {
			kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
		} else {
			kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
		}
		flag.Parse()
		config_out_cluster, _ := clientcmd.BuildConfigFromFlags("", *kubeconfig)
		return config_out_cluster
	}

	return nil
}

// Called by the main () function in its step (1). This method fetch the Metrics.csv file from RTE which contains REST and/or gRPC microservice-to-microservice communications	get_metrics_from_RTE()
func get_metrics_from_RTE() {

	_, err := os.Stat("Metrics.csv")
	if err != nil {
		if os.IsNotExist(err) {
			if flag_ {
				fmt.Println("The file does not exist. Call the service RTE as this: http://rte:8099/SDG")

				resp, err := http.Get("http://rte:8099/SDG")
				if err != nil {
					fmt.Println(err)
				}
				defer resp.Body.Close()

				body, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					fmt.Println(err)
				}
				fmt.Println(string(body))
				f, err := os.Create("Metrics.csv")
				if err != nil {
					panic(err)
				}
				// Write the string to the Metrics file
				_, err = f.WriteString(string(body))
				if err != nil {
					panic(err)
				}
				// Close the file
				err = f.Close()
				if err != nil {
					panic(err)
				}

			} else {
				fmt.Println("The file does not exist. Call the service RTE as this: http://localhost:8099/SDG")
				resp_, err_ := http.Get("http://localhost:8099/SDG")
				if err_ != nil {
					fmt.Println(err_)
				}
				defer resp_.Body.Close()

				body_, err__ := ioutil.ReadAll(resp_.Body)
				if err__ != nil {
					fmt.Println(err__)
				}

				fmt.Println(string(body_))

				f, err____ := os.Create("Metrics.csv")
				if err____ != nil {
					panic(err____)
				}

				// Write the string to the Metrics file
				_, err = f.WriteString(string(body_))
				if err != nil {
					panic(err)
				}

				// Close the file
				err = f.Close()
				if err != nil {
					panic(err)
				}

			}

		} else {
			fmt.Println("The file is exist", err)
		}
	} else {
		fmt.Println("The Metrics.csv file exists. No need to get it again")
	}
	fmt.Println("----------- The Metrics values just extracted from Metrics.csv file.-----------")
}

// Called by the main () function in its step (2). Create least privileges access policies
func create_Cache_and_AP_Cases_1_2_3() {
	log.Println(" --------------------------- In  create_Cache_and_AP_Cases_1_2_3 () --------------------------- start")
	if len(c.Items()) != 0 {
		log.Println("------------- Cache is exist. No need to do it again.")
	} else {
		log.Println("------------- Cache does not exist. In the process to create it.")
		// Read the CSV file.
		log.Println("------------- To read the Metrics.csv file")
		data, err := ioutil.ReadFile("Metrics.csv")
		if err != nil {
			fmt.Println(err)
		}
		lines := strings.Split(string(data), "\n")
		log.Println("------------- Here is the Metrics data as a list:", lines)

		// return the Metrics.csv as a list

		for _, line := range lines {
			log.Println("------------- Now go through a loop for each line in Metrics.csv (list I mean)")
			//log.Println("Each line value:", line)
			if strings.Contains(line, "Microservice_name") {
				log.Println("------------- If the first line is Microservice_name, then skip the processing")
			} else {
				log.Println("------------- Now APG handles the line: ", line)
				if line != "" {

					// $ used to split from canAccess and values before
					CRUD_grpc_connections := strings.Split(line, "$")
					log.Println("------------- Now APG trying to get all CRUD/gRPC connection by splitting with $: CRUD_grpc_connections=", CRUD_grpc_connections)

					line_value_split := strings.Split(line, ",")
					log.Println("------------- APG split the lien by , as line_value_split: ", line_value_split)

					// Get can access from each microservice-to-microservice in both REST and gRPC
					log.Println("------------- APG now has the info for each microservice such as:", line_value_split[0], " that has CRUD_grpc_connections[1] : ", CRUD_grpc_connections[1])

					// Check if there are no REST CRUD or gRPC.
					if CRUD_grpc_connections[1] == ":@\"" {
						log.Println("------------- Microservice", line_value_split[0], "has no access to REST nor gRPC")

						//  Case 1: Least privilege. Disallow all access.
						log.Println("-------------  Make AP creation for microservice:", string(line_value_split[0]), " and the result of calling case1 method ():", case1(strings.Replace(string(line_value_split[0]), "\"", "", -1)))

						// Set the in memory allowed AC policies for microservice to be nothing.
						log.Println("-------------  Set the in memory allowed AC policies for microservice to be nothing:")
						c.Set(string(line_value_split[0]), "NA", cache.DefaultExpiration)

					} else {
						log.Println("-------------  There are some REST/gRPC connections. Need to create AC policies")

						// Set in memory data set the current microservice name and all trusted CanAccess.

						c.Set(string(line_value_split[0]), string(CRUD_grpc_connections[1]), cache.DefaultExpiration)
						log.Println("list_temp type:::::", reflect.TypeOf(CRUD_grpc_connections))
						// Case 2: create the least privilege access for both REST and/or gRPC AC policies for each legit operations from microservice (list[0]) to other microservices.
						log.Println("Make AP creation for:", string(line_value_split[0]), " and the result:", case2(string(line_value_split[0]), service_and_theirCRUD_grpc(string(CRUD_grpc_connections[1]), string(line_value_split[0])), CRUD_grpc_connections[1]))

						// Case 3: after given the least privilege access, deny other access to other microservices.
						case3(string(line_value_split[0]), service_and_theirCRUD_grpc(string(CRUD_grpc_connections[1]), string(line_value_split[0])), lines)

					}
				}
			}
		}
		fmt.Println("************************PRINTING THE Cache************************")
	}
	log.Println(" #################################### APG Function: creareCache() #################################### end")
}

// Called by the main () function in its step (3). This method helps to create RAdAC AC policies.
func create(con *gin.Context) {
	log.Println("************************************ In create() method ************************************")
	//http://localhost:9770/create?MS=teastore-webui&TM=90
	log.Println("************************************", con.Request.URL.Query(), "******************************")

	// Get request parameters
	parameters := con.Request.URL.Query()

	// Convert TM from String to float 64
	TM_, _ := strconv.ParseFloat(strings.Join(parameters["TM"], ""), 64)

	// Call RAdAC to make the right AC policies given MS name and TM value as float
	RAdAC(strings.Join(parameters["MS"], ""), TM_)

	// When called, return the below message
	con.IndentedJSON(http.StatusOK, gin.H{"message": "AuthorizationPolicy was created"})
}

// Case 1: createAllowNothing AC policy
func case1(Service_name string) string {
	log.Println("In case1() function: Create an AuthorizationPolicy policy to allow nothing for microservice name:", Service_name)

	// Get the connection
	config := getConneciton(flag_)

	// temp variable to hold a autCreate3.Status
	var status = ""
	// Create the AuthorizationPolicyName
	var AuthorizationPolicyName_allow_nothing = ""
	AuthorizationPolicyName_allow_nothing = "allow-nothing-" + Service_name + "-toward-all"

	sourcelist := []string{}
	//ops_ := []string{}
	//ops_ = append(ops_, "POST", "PUT", "DELETE")

	// Prepare the source name as "cluster.local/ns/default/sa/sa
	sourcelist = append(sourcelist, fmt.Sprint(strings.ToLower("cluster.local/ns/default/sa/"+strings.Replace(Service_name, "\"", "", -1))))

	// Deny all for both REST and gRPC.
	ops_deny_all := []string{}
	ops_deny_all = append(ops_deny_all, "GET")
	ops_deny_all = append(ops_deny_all, "PUT")
	ops_deny_all = append(ops_deny_all, "DELETE")
	ops_deny_all = append(ops_deny_all, "POST")

	deployment_apply_nothong := &v1beta3.AuthorizationPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: AuthorizationPolicyName_allow_nothing +
				"",
			Namespace: "default",
		},
		Spec: securityv1beta1.AuthorizationPolicy{

			Action: securityv1beta1.AuthorizationPolicy_DENY,
			Rules: []*securityv1beta1.Rule{{
				From: []*securityv1beta1.Rule_From{{
					Source: &securityv1beta1.Source{
						Principals: sourcelist,
					},
				}},
				To: []*securityv1beta1.Rule_To{{
					Operation: &securityv1beta1.Operation{
						Methods: ops_deny_all,
					},
				},
				},
			},
			},
		},
	}

	icc, err := versionedclient.NewForConfig(config)

	// Go ahead and apply the created AllowNothing AC policy.
	autCreate3, err := icc.SecurityV1beta1().AuthorizationPolicies("default").Create(
		context.TODO(),
		deployment_apply_nothong,
		metav1.CreateOptions{},
	)
	status = autCreate3.Status.String()
	fmt.Println("AllowNothing policy created status:", autCreate3.Status)
	//fmt.Println("autCreate Spec = ", autCreate.Spec)
	//fmt.Println("autCreate GetName = ", autCreate.GetName())
	//fmt.Println("autCreate GetGenerateName = ", autCreate.GetGenerateName())
	//fmt.Println("autCreate GetAnnotations = ", autCreate.GetAnnotations())
	if err != nil {
		//return fmt.Errorf("Failed to create AuthorizationPolicies in namespace %s", err)
		log.Printf("Failed to create AllowNothing AuthorizationPolicies in namespace %s\", err\n")
		log.Println(err)

	}
	return status
}

// Case 2: createAP_legit
func case2(SS string, TS map[string]string, CanAccess string) string {
	log.Println("in case2() function.")
	log.Println("CanAccess:", CanAccess)
	log.Println("TS:", TS)

	log.Println("Microservice name:", SS)
	log.Println("Allowed trsutued Microservices:", TS)
	var isItgRPC bool = false

	sourcelist := []string{}
	// Make the source name in proper K8s format.
	sourcelist = append(sourcelist, fmt.Sprint(strings.ToLower("cluster.local/ns/default/sa/"+strings.Replace(SS, "\"", "", -1))))

	// Get K8s connection.
	config := getConneciton(flag_)
	icc2, _ := versionedclient.NewForConfig(config)
	for k, v := range TS {
		ops := []string{}
		print("key[%s] value[%s]")

		fmt.Printf("key[%s] value[%s]", k, v)
		if strings.Contains(v, "GET") {
			ops = append(ops, "GET")
		}
		log.Println("RAMI Mstrings.Contains(v, \"POST\")==", strings.Contains(v, "POST"))
		log.Println("RAMI v===", v)

		if strings.Contains(v, "POST") {

			// Here check if it is REST or just gRPC.
			// if it has gRPC, then it is gRPC. Otherwide it is just REST.
			log.Println("strings.Contains(v, \"grpc\")====", strings.Contains(v, "grpc"))

			if strings.Contains(v, "grpc") {
				log.Println("It has gRPC.")
				isItgRPC = true

			} else {
				log.Println("It has gRPC.")

				isItgRPC = false
				// Keep it as it is.
				log.Println("It is just REST")
			}
			ops = append(ops, "POST")
		}
		if strings.Contains(v, "DELETE") {
			ops = append(ops, "DELETE")
		}
		if strings.Contains(v, "PUT") {
			ops = append(ops, "PUT")
		}
		log.Println("ops[]=", ops)

		// If the ops list has at least one operation, then go ahead with the processing.
		if len(ops) >= 1 {

			// here you need to check if the previous check found it gRPC or REST.
			if isItgRPC {
				// Do gRPC
				log.Println("gRPC ±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±± v====", v)
				log.Println("From MS:", SS)
				log.Println("To MS:", k)
				//  split then take each one pathRequest.
				temp_all_pathRequests := strings.Split(fmt.Sprintf("%v", v), "~,")
				pathRequests := strings.Split(fmt.Sprintf("%v", temp_all_pathRequests[1]), ",")
				log.Println("pathRequests:", pathRequests)
				// Do for loop then create Auth policy as REST but with putting Request paths
				var AuthorizationPolicyName_allow_only_legit_grpc = ""
				AuthorizationPolicyName_allow_only_legit_grpc = "allow-only-grpc-" + strings.Replace(SS, "\"", "", -1) + "-toward-" + k
				ops_post := []string{}
				ops_post = append(ops_post, "POST")

				deployment_grpc := &v1beta3.AuthorizationPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name: AuthorizationPolicyName_allow_only_legit_grpc +
							"",
						Namespace: "default",
					},
					Spec: securityv1beta1.AuthorizationPolicy{
						Selector: &v1beta1.WorkloadSelector{
							MatchLabels: map[string]string{
								"app": k,
							},
						},
						Action: securityv1beta1.AuthorizationPolicy_ALLOW,
						Rules: []*securityv1beta1.Rule{{
							From: []*securityv1beta1.Rule_From{{
								Source: &securityv1beta1.Source{
									Principals: sourcelist,
								},
							}},
							To: []*securityv1beta1.Rule_To{{

								Operation: &securityv1beta1.Operation{
									Methods: ops_post,
									Paths:   pathRequests,
								},
							},
							},
						},
						},
					},
				}
				//
				autCreate2_grpc, _ := icc2.SecurityV1beta1().AuthorizationPolicies("default").Create(
					context.TODO(),
					deployment_grpc,
					metav1.CreateOptions{},
				)
				log.Println("autCreate2_grpc.GetName()=", autCreate2_grpc.GetName())                           // keep it as it is.
				log.Println("autCreate2_grpc.GetCreationTimestamp()=", autCreate2_grpc.GetCreationTimestamp()) // keep it as it is.

			} else {
				// If it is REST, keep it.
				log.Println("Create REST operations")

				var AuthorizationPolicyName_allow_only_legit = ""
				AuthorizationPolicyName_allow_only_legit = "allow-only-" + strings.Replace(SS, "\"", "", -1) + "-toward-" + k

				log.Println("TS k value=", k)

				deployment2 := &v1beta3.AuthorizationPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name: AuthorizationPolicyName_allow_only_legit +
							"",
						Namespace: "default",
					},
					Spec: securityv1beta1.AuthorizationPolicy{
						Selector: &v1beta1.WorkloadSelector{
							MatchLabels: map[string]string{
								"app": k,
							},
						},
						Action: securityv1beta1.AuthorizationPolicy_ALLOW,
						Rules: []*securityv1beta1.Rule{{
							From: []*securityv1beta1.Rule_From{{
								Source: &securityv1beta1.Source{
									Principals: sourcelist,
								},
							}},
							To: []*securityv1beta1.Rule_To{{

								Operation: &securityv1beta1.Operation{
									Methods: ops,
								},
							},
							},
						},
						},
					},
				}

				fmt.Println("case2() created AuthorizationPolicy_ALLOW = ", deployment2)
				autCreate2, _ := icc2.SecurityV1beta1().AuthorizationPolicies("default").Create(
					context.TODO(),
					deployment2,
					metav1.CreateOptions{},
				)
				log.Println("autCreate2=", autCreate2.GetName()) // keep it as it is.
			}

		} else {
			log.Println("ELSE: len(ops) <= 0")
		}

	}

	//fmt.Println("autCreate Spec = ", autCreate.Spec)
	//fmt.Println("autCreate GetName = ", autCreate.GetName())
	//fmt.Println("autCreate GetGenerateName = ", autCreate.GetGenerateName())
	//fmt.Println("autCreate GetAnnotations = ", autCreate.GetAnnotations())

	/////////
	log.Println(" #################################### APG Function: AuthorizationPolicyName() #################################### end")

	return "Done"
}

// Case 3: Deny all from the SS to other services.
func case3(SS string, TS map[string]string, list []string) {
	log.Println(" #################################### APG Function: case3 #################################### start")
	log.Println("TS===", TS)
	log.Println("list===", list)

	// Go find all microservices that has connection to the microservice in question.
	AllSerivce_names := []string{}
	Services_that_has_connection_to_the_ss := []string{}
	Services_that_has_NO_connection_to_the_ss := []string{}
	AllSerivce_names = append(AllSerivce_names, "")
	for key := range TS {
		Services_that_has_connection_to_the_ss = append(Services_that_has_connection_to_the_ss, "\""+key+"\"")
	}

	// Then go get all other Microservices in the deployed MSA application.
	for _, line := range list {
		//log.Println("Each line value:", line)
		if strings.Contains(line, "Microservice_name") {
		} else {
			list := strings.Split(line, ",")
			AllSerivce_names = append(AllSerivce_names, list[0])

		}
	}
	// Now the below will get the result of Microservices that have not legit access or need.
	Services_that_has_NO_connection_to_the_ss = difference(Services_that_has_connection_to_the_ss, AllSerivce_names, SS)

	log.Println("Services_that_has_connection_to_the_ss=", Services_that_has_connection_to_the_ss)
	log.Println("Services_that_has_NO_connection_to_the_ss=", Services_that_has_NO_connection_to_the_ss)

	for ot := range Services_that_has_NO_connection_to_the_ss {

		config := getConneciton(flag_)
		var AuthorizationPolicyName_deny_all_from_service_to_others = ""
		AuthorizationPolicyName_deny_all_from_service_to_others = "deny-all-from-" + strings.Replace(SS, "\"", "", -1) + "-toward-" + strings.Replace(Services_that_has_NO_connection_to_the_ss[ot], "\"", "", -1)
		log.Println("AuthorizationPolicyName_deny_all_from_service_to_others=", AuthorizationPolicyName_deny_all_from_service_to_others)

		sourcelist := []string{}
		ops_ := []string{}
		ops_ = append(ops_, "POST", "PUT", "DELETE", "GET")
		sourcelist = append(sourcelist, fmt.Sprint(strings.ToLower("cluster.local/ns/default/sa/"+strings.Replace(SS, "\"", "", -1))))
		log.Println("Final_clean_list[ot]=", strings.Replace(Services_that_has_NO_connection_to_the_ss[ot], "\"", "", -1))

		deployment2 := &v1beta3.AuthorizationPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: AuthorizationPolicyName_deny_all_from_service_to_others +
					"",
				Namespace: "default",
			},
			Spec: securityv1beta1.AuthorizationPolicy{
				Selector: &v1beta1.WorkloadSelector{
					MatchLabels: map[string]string{
						"app": strings.Replace(Services_that_has_NO_connection_to_the_ss[ot], "\"", "", -1),
					},
				},
				Action: securityv1beta1.AuthorizationPolicy_DENY,
				Rules: []*securityv1beta1.Rule{{
					From: []*securityv1beta1.Rule_From{{
						Source: &securityv1beta1.Source{
							Principals: sourcelist,
						},
					}},
					To: []*securityv1beta1.Rule_To{{

						Operation: &securityv1beta1.Operation{
							Methods: ops_,
						},
					},
					},
				},
				},
			},
		}
		icc2, _ := versionedclient.NewForConfig(config)
		fmt.Println("case3() AuthorizationPolicy = ", deployment2)
		autCreate2, erro := icc2.SecurityV1beta1().AuthorizationPolicies("default").Create(
			context.TODO(),
			deployment2,
			metav1.CreateOptions{},
		)
		log.Println("autCreate.GetName()= ", autCreate2.GetName())
		if erro != nil {
			//return fmt.Errorf("Failed to create AuthorizationPolicies in namespace %s", err)
			log.Println("Failed to create AuthorizationPolicies in namespace %s\", err")
			log.Println(erro)

		}

	}

}

// Delete AP
func deleteAP(AP string) {
	log.Println("************************************ in deleteAP() ***********************************")
	log.Println("AP===", AP)

	config := getConneciton(flag_)

	icc, err := versionedclient.NewForConfig(config)

	icc.SecurityV1beta1().AuthorizationPolicies("default").Delete(
		context.TODO(),
		AP,
		metav1.DeleteOptions{},
	)

	if err != nil {
		//return fmt.Errorf("Failed to create AuthorizationPolicies in namespace %s", err)
		log.Println("Failed to delete AuthorizationPolicies in deleteAP() namespace %s\", err")
		log.Println(err)
	} else {
		fmt.Println("AuthorizationPolicy deleted successfully")
	}
	/////////

}

// Case 4: adaptivecase REST
func adaptivecase(SS string, ops_ []string, TS string) string {

	sourcelist := []string{}
	//ops_ := []string{}
	//ops_ = append(ops_, "POST", "PUT", "DELETE")
	sourcelist = append(sourcelist, fmt.Sprint(strings.ToLower("cluster.local/ns/default/sa/"+strings.Replace(SS, "\"", "", -1))))

	//log.Println("AuthorizationPolicyName=", AuthorizationPolicyName)
	//log.Println("trustscore=", trustscore)
	//log.Println("TS=", TS)
	// Create AuthorizationPolicy

	config := getConneciton(flag_)

	ops := []string{}
	if strings.Contains(strings.Join(ops_, ""), "GET") {
		ops = append(ops, "GET")
	}
	if strings.Contains(strings.Join(ops_, ""), "POST") {
		ops = append(ops, "POST")
	}
	if strings.Contains(strings.Join(ops_, ""), "DELETE") {
		ops = append(ops, "DELETE")
	}
	if strings.Contains(strings.Join(ops_, ""), "PUT") {
		ops = append(ops, "PUT")
	}

	if len(ops) >= 1 {
		////

		var AuthorizationPolicyName_allow_only_legit = ""
		AuthorizationPolicyName_allow_only_legit = "allow-only-" + strings.Replace(SS, "\"", "", -1) + "-toward-" + TS

		deployment2 := &v1beta3.AuthorizationPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: AuthorizationPolicyName_allow_only_legit +
					"",
				Namespace: "default",
			},
			Spec: securityv1beta1.AuthorizationPolicy{
				Selector: &v1beta1.WorkloadSelector{
					MatchLabels: map[string]string{
						"app": TS,
					},
				},
				Action: securityv1beta1.AuthorizationPolicy_ALLOW,
				Rules: []*securityv1beta1.Rule{{
					From: []*securityv1beta1.Rule_From{{
						Source: &securityv1beta1.Source{
							Principals: sourcelist,
						},
					}},
					To: []*securityv1beta1.Rule_To{{

						Operation: &securityv1beta1.Operation{
							Methods: ops,
						},
					},
					},
				},
				},
			},
		}
		icc2, _ := versionedclient.NewForConfig(config)
		fmt.Println("Istio: adaptivecase(1) AuthorizationPolicy = ", deployment2)
		autCreate2, _ := icc2.SecurityV1beta1().AuthorizationPolicies("default").Create(
			context.TODO(),
			deployment2,
			metav1.CreateOptions{},
		)

		log.Println("autCreate.GetName()= ", autCreate2.GetName())

	} else {
		ops_deny_all := []string{}
		ops_deny_all = append(ops_deny_all, "GET")
		ops_deny_all = append(ops_deny_all, "POST")
		ops_deny_all = append(ops_deny_all, "PUT")
		ops_deny_all = append(ops_deny_all, "DELETE")

		var AuthorizationPolicyName_allow_only_legit = ""
		AuthorizationPolicyName_allow_only_legit = "deny-all-from-" + strings.Replace(SS, "\"", "", -1) + "-toward-" + TS

		deployment2 := &v1beta3.AuthorizationPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: AuthorizationPolicyName_allow_only_legit +
					"",
				Namespace: "default",
			},
			Spec: securityv1beta1.AuthorizationPolicy{
				Selector: &v1beta1.WorkloadSelector{
					MatchLabels: map[string]string{
						"app": TS,
					},
				},
				Action: securityv1beta1.AuthorizationPolicy_DENY,
				Rules: []*securityv1beta1.Rule{{
					From: []*securityv1beta1.Rule_From{{
						Source: &securityv1beta1.Source{
							Principals: sourcelist,
						},
					}},
					To: []*securityv1beta1.Rule_To{{

						Operation: &securityv1beta1.Operation{
							Methods: ops_deny_all,
						},
					},
					},
				},
				},
			},
		}
		icc2, _ := versionedclient.NewForConfig(config)
		fmt.Println("adaptivecase(2) AuthorizationPolicy =  = ", deployment2)
		autCreate2, _ := icc2.SecurityV1beta1().AuthorizationPolicies("default").Create(
			context.TODO(),
			deployment2,
			metav1.CreateOptions{},
		)

		log.Println("autCreate.GetName()= ", autCreate2.GetName())

		log.Println("ELSE: len(ops) <= 0. No adaptive AP policies needed")
	}

	//fmt.Println("autCreate Spec = ", autCreate.Spec)
	//fmt.Println("autCreate GetName = ", autCreate.GetName())
	//fmt.Println("autCreate GetGenerateName = ", autCreate.GetGenerateName())
	//fmt.Println("autCreate GetAnnotations = ", autCreate.GetAnnotations())

	/////////

	return "Done"
}

// Case: adaptive gRPC (allowed)
func adaptivegRPC_adaptivegRPC_allow(MS string, victim_microservice string, requestPaths_items []string) string {
	sourcelist := []string{}
	ops_post := []string{}
	ops_post = append(ops_post, "POST")
	sourcelist = append(sourcelist, fmt.Sprint(strings.ToLower("cluster.local/ns/default/sa/"+strings.Replace(MS, "\"", "", -1))))

	config := getConneciton(flag_)

	if len(requestPaths_items) > 1 {

		var AuthorizationPolicyName_allow_only_legit = ""
		AuthorizationPolicyName_allow_only_legit = "adaptive-allow-only-" + strings.Replace(MS, "\"", "", -1) + "-toward-" + victim_microservice

		deployment2 := &v1beta3.AuthorizationPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: AuthorizationPolicyName_allow_only_legit +
					"",
				Namespace: "default",
			},
			Spec: securityv1beta1.AuthorizationPolicy{
				Selector: &v1beta1.WorkloadSelector{
					MatchLabels: map[string]string{
						"app": victim_microservice,
					},
				},
				Action: securityv1beta1.AuthorizationPolicy_ALLOW,
				Rules: []*securityv1beta1.Rule{{
					From: []*securityv1beta1.Rule_From{{
						Source: &securityv1beta1.Source{
							Principals: sourcelist,
						},
					}},
					To: []*securityv1beta1.Rule_To{{

						Operation: &securityv1beta1.Operation{
							Methods: ops_post,
							Paths:   requestPaths_items,
						},
					},
					},
				},
				},
			},
		}

		icc2, _ := versionedclient.NewForConfig(config)
		fmt.Println("Istio: adaptivecase(1) AuthorizationPolicy = ", deployment2)
		autCreate2, erro := icc2.SecurityV1beta1().AuthorizationPolicies("default").Create(
			context.TODO(),
			deployment2,
			metav1.CreateOptions{},
		)
		if erro != nil {
			//return fmt.Errorf("Failed to create AuthorizationPolicies in namespace %s", err)
			log.Println("Failed to create AuthorizationPolicies in namespace %s\", err")
			log.Println(erro)

		} else {
			log.Println("Adaptive AC policy got created.")
		}

		log.Println("autCreate.GetName()= ", autCreate2.GetName())

	}

	return "Done"
}

// Case: adaptive gRPC (disallowd)
func adaptivegRPC_adaptivegRPC_disallow(MS string, victim_microservice string, requestPaths_items []string) string {
	log.Println("((((((((((((((((((((((((( in adaptivegRPC_adaptivegRPC_disallow() )))))))))))))))))))))")
	log.Println("MS====", MS)
	log.Println("victim_microservice====", victim_microservice)
	log.Println("requestPaths_items====", requestPaths_items)

	sourcelist := []string{}
	ops_post := []string{}
	ops_post = append(ops_post, "POST")
	sourcelist = append(sourcelist, fmt.Sprint(strings.ToLower("cluster.local/ns/default/sa/"+strings.Replace(MS, "\"", "", -1))))

	config := getConneciton(flag_)

	var AuthorizationPolicyName_allow_only_legit = ""
	AuthorizationPolicyName_allow_only_legit = "adaptive-disallow-only-" + strings.Replace(MS, "\"", "", -1) + "-toward-" + victim_microservice
	log.Println("AuthorizationPolicyName_allow_only_legit====", AuthorizationPolicyName_allow_only_legit)

	deployment2 := &v1beta3.AuthorizationPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: AuthorizationPolicyName_allow_only_legit +
				"",
			Namespace: "default",
		},
		Spec: securityv1beta1.AuthorizationPolicy{
			Selector: &v1beta1.WorkloadSelector{
				MatchLabels: map[string]string{
					"app": victim_microservice,
				},
			},
			Action: securityv1beta1.AuthorizationPolicy_DENY,
			Rules: []*securityv1beta1.Rule{{
				From: []*securityv1beta1.Rule_From{{
					Source: &securityv1beta1.Source{
						Principals: sourcelist,
					},
				}},
				To: []*securityv1beta1.Rule_To{{

					Operation: &securityv1beta1.Operation{
						Methods: ops_post,
						Paths:   requestPaths_items,
					},
				},
				},
			},
			},
		},
	}

	icc2, _ := versionedclient.NewForConfig(config)
	fmt.Println("Istio: adaptivecase(1) AuthorizationPolicy = ", deployment2)
	autCreate2, erro := icc2.SecurityV1beta1().AuthorizationPolicies("default").Create(
		context.TODO(),
		deployment2,
		metav1.CreateOptions{},
	)
	if erro != nil {
		//return fmt.Errorf("Failed to create AuthorizationPolicies in namespace %s", err)
		log.Println("Failed to create AuthorizationPolicies in namespace %s\", err")
		log.Println(erro)

	} else {
		log.Println("Adaptive AC policy got created (disallow.")
	}

	log.Println("autCreate.GetName()= ", autCreate2.GetName())

	return "Done"
}

func getConfigMap_class_name(MS string) string {

	log.Println("MS=========== ", MS)
	var return_value = ""
	namespace := apiv1.NamespaceDefault
	config := getConneciton(flag_)
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}
	if err != nil {
		log.Fatalf("Failed to get start K8s connection in  getConfigMap_class_name() in %s namespace: %s", namespace, err)
	}
	deploymentsClient := clientset.AppsV1().Deployments(apiv1.NamespaceDefault)

	retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		// Retrieve the latest version of Deployment before attempting update
		// RetryOnConflict uses exponential backoff to avoid exhausting the apiserver
		result, getErr := deploymentsClient.Get(context.TODO(), MS, metav1.GetOptions{})
		if getErr != nil {
			panic(fmt.Errorf("Failed to get latest version of Deployment in getConfigMap_class_name(): %v", getErr))
		}

		return_value = result.Labels["s"]
		// reduce replica count
		_, updateErr := deploymentsClient.Update(context.TODO(), result, metav1.UpdateOptions{})
		return updateErr
	})
	if retryErr != nil {
		panic(fmt.Errorf("Update failed: %v", retryErr))
	}
	return return_value
}

// This function helps to get compliance requirements pushed by microservices owners and then stored by APG as configmp
func getConfigMap(class_s string, IsitgRPC bool) map[string]string {
	configmap_values := map[string]string{}
	log.Println("######################## In getConfigMap() ########################")

	namespace := apiv1.NamespaceDefault
	config := getConneciton(flag_)
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}
	configmap, _ := clientset.CoreV1().ConfigMaps("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		log.Fatalf("Failed to get get K8s connection in getConfigMap() %s namespace: %s", namespace, err)
	}

	// Search all configmaps, then if the label name equals to class_s, return the CRUDO
	for i := range configmap.Items {
		vs := configmap.Items[i]

		_, ok_REST := vs.Data["D"]
		_, ok_gRPC := vs.Data["P"]

		// If the key exists
		if ok_REST || ok_gRPC {
			if vs.Labels["s"] == class_s {
				if IsitgRPC {
					configmap_values = map[string]string{
						"P":  vs.Data["P"],
						"O":  vs.Data["M"],
						"TM": vs.Data["T"],
					}

					// do gRPC
				} else {
					// Do REST
					configmap_values = map[string]string{
						"GET":    vs.Data["G"],
						"POST":   vs.Data["P"],
						"PUT":    vs.Data["U"],
						"DELETE": vs.Data["D"],
						"TM":     vs.Data["T"],
					}
					break
				}

			} else {
			}
		}
	}
	if len(configmap_values) < 1 {
		if IsitgRPC {
			// Do Equal split of 100% to all request paths gRPC
			/// oooooo
			// default is to divided 100 to number of requests paths 30% for each
			configmap_values = map[string]string{
				"P":  "15",
				"O":  "S",
				"TM": "40",
			}
		} else {
			// do REST
			log.Println("Does not found the S label for class:", class_s, " give default values")
			configmap_values = map[string]string{
				"GET":    "25",
				"POST":   "25",
				"PUT":    "25",
				"DELETE": "25",
				"TM":     "40",
			}
		}

		return configmap_values
	} else {
		log.Println("Found the S label for class:", class_s, " and here is the values:", configmap_values)

		return configmap_values
	}

}

func getItemFromCache(con *gin.Context) {
	log.Println("----------------------------------------------------")

	log.Println(con.Request.URL.Query())
	parameters := con.Request.URL.Query()

	value, _ := c.Get(strings.Join(parameters["MS"], ""))

	con.IndentedJSON(http.StatusOK, gin.H{"message": value})

}

func RAdAC(MS string, TM_MS float64) {
	log.Println("************************************ In create() method ************************************")

	// Return if the MS follows gRPC or REST
	var IsItgRPC_ = IsItgRPC("\"" + MS + "\"")

	// Get class name (s) for the MS
	S_level := getConfigMap_class_name(MS)

	///////////////////////// Start of gRPC RdAC ///////////////////////////////////////
	if IsItgRPC_ {

		// Get compliance_requirements for MS to get TM_acceptable + price to spend and perfect method of spending (equal spend or to most important request paths_
		get_imposed_compliance_requirements := getConfigMap(S_level, IsItgRPC_)
		var TM_acceptable_grpc = 0.0
		var Price_to_spend_P = 0.0

		TM_acceptable_grpc, _ = strconv.ParseFloat(strings.TrimSpace(get_imposed_compliance_requirements["TM"]), 64)
		Price_to_spend_P, _ = strconv.ParseFloat(strings.TrimSpace(get_imposed_compliance_requirements["P"]), 64)
		log.Println("±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±± gRPC ±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±")
		log.Println("±±±±±±±±±±±±±±±± TM_acceptable_TM:", TM_acceptable_grpc)
		log.Println("±±±±±±±±±±±±±±±± Price_to_spend_P:", Price_to_spend_P)

		// Get all victim microservices or possible targeted.
		Victim_Microservices, _ := c.Get("\"" + MS + "\"")
		log.Println("±±±±±±±±±±±± GOLD ±±±±±±±±±± Victim_Microservices=====", Victim_Microservices)
		destintion_microservicename := strings.Split(fmt.Sprintf("%v", Victim_Microservices), "@")
		log.Println("±±±±±±±±±±±±± GOLD ±±±±±±±±±destintion_microservicename:", destintion_microservicename)
		destintion_microservicename_ := strings.Fields(strings.Trim(strings.Join(destintion_microservicename, " "), "[] "))
		log.Println("±±±±±±±±±±±±±±±±±±±±±± GOLD ±±±±±±±±±±±destintion_microservicename_:", destintion_microservicename_)
		if TM_MS >= TM_acceptable_grpc {
			log.Println("gRPC: no need to create any AP. TM_MS >= TM_MS (", TM_MS, ">=", TM_acceptable_grpc, ")")
		} else {
			log.Println("gRPC: need to create AP. TM_MS >= TM_acceptable_grpc")

			// Find the number of all request paths in all trsuted request paths
			var counter_of_request_paths float64 = 0.0
			var cost_per_request_on_scale_of_100_as_default = 0.0

			// The below code helps to find the number of request paths to find the cost of each one
			// saved the result as: counter_of_request_paths
			for _, entry := range destintion_microservicename_ {
				// Here it shows each line such as: [currencyservice:POST[grpc~,/hipstershop.CurrencyService/GetSupportedCurrencies,/hipstershop.CurrencyService/Convert
				var count float64 = 0.0
				// Get victim_microservice name for each one and gRPC paths as a list
				victim_microservice := strings.Split(entry, ":")
				if len(victim_microservice) > 1 {
					log.Println("Victim MS=", victim_microservice[0])
					requestPaths := strings.Split(victim_microservice[1], "grpc~,")

					// If there are request paths
					if len(requestPaths) > 1 {
						// Then get them in order as a list for the MS under review
						items := strings.Split(strings.TrimSpace(requestPaths[1]), ",")
						log.Println("Victim MS gRPC request Paths=", items)
						// get the count of request paths and saved it as
						for _, item := range items {
							if strings.TrimSpace(item) != "" { // Ignore empty items
								count++
							}
						}
						counter_of_request_paths = counter_of_request_paths + count
						fmt.Println("counter_of_request_paths=====", counter_of_request_paths) // Print only the part before ":"

					} else {
						log.Println("No request paths for victim microservices: ", victim_microservice[0])

					}
				}
			}
			cost_per_request_on_scale_of_100_as_default = 100 / counter_of_request_paths
			log.Println("counter_of_request_paths=====", counter_of_request_paths)

			log.Println("cost_per_request=", cost_per_request_on_scale_of_100_as_default)
			log.Println("cost_per_request based on P as (", Price_to_spend_P, ") costs per request path:", Price_to_spend_P/counter_of_request_paths)
			for _, entry := range destintion_microservicename_ {
				victim_microservices := strings.Split(entry, ":")
				if len(victim_microservices) > 1 {
					requestPaths := strings.Split(victim_microservices[1], "grpc~,")

					if len(requestPaths) > 1 {
						requestPaths_items := strings.Split(strings.TrimSpace(requestPaths[1]), ",")
						log.Println(">>>>>>  Handling victim MS", victim_microservices[0], " Request requestPaths_items=", requestPaths_items)
						// Delete allowd AC
						log.Println("allow-only-grpc-" + strings.Replace(MS, "\"", "", -1) + "-toward-" + victim_microservices[0])
						deleteAP("allow-only-grpc-" + strings.Replace(MS, "\"", "", -1) + "-toward-" + victim_microservices[0])
						// Spend the price here on all request paths until no more balance
						log.Println("Price_to_spend_P > 0====", Price_to_spend_P > 0)
						if Price_to_spend_P > 0 && Price_to_spend_P >= cost_per_request_on_scale_of_100_as_default {
							log.Println("Price_to_spend_P before=====", Price_to_spend_P)
							Price_to_spend_P = Price_to_spend_P - (cost_per_request_on_scale_of_100_as_default * float64(len(requestPaths_items)))
							log.Println("Price_to_spend_P after=====", Price_to_spend_P)
							log.Println("Create adaptive AC")
							adaptivegRPC_adaptivegRPC_allow(MS, victim_microservices[0], requestPaths_items)
						} else {
							var requestPaths_items2 []string
							log.Println("Create adaptive AC disallow - no more price can afford reamaning paths")
							adaptivegRPC_adaptivegRPC_disallow(MS, victim_microservices[0], requestPaths_items2)
						}

					} else {

						log.Println("No request paths for victim microservices: ", victim_microservices[0])
						var requestPaths_items []string
						adaptivegRPC_adaptivegRPC_disallow(MS, victim_microservices[0], requestPaths_items)

					}

				}
			}

			////
			log.Println("End-MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM")

		}
		//////////////////////////////////////////// End of gRPC ////////////////////////////////////////////////
	} else {
		// Do REST. Keep as it is.
		get_CRUD := getConfigMap(S_level, IsItgRPC_)
		log.Println("RAdAC function: S level for MS=", MS, " is equals=", S_level, " and CRUD=", get_CRUD)
		var TM_acceptable = 0.0
		TM_acceptable, _ = strconv.ParseFloat(strings.TrimSpace(get_CRUD["TM"]), 64)
		victimsservicesNames, _ := c.Get("\"" + MS + "\"")
		if TM_MS >= TM_acceptable {
			log.Println("RAdAC function(): no need to create any AP. TM_MS >= TM_MS (", TM_MS, ">=", TM_acceptable, ")")
		} else {
			log.Println("RAdAC function (): c.Items() before any process:", c.Items())
			log.Println("RAdAC function(): Need to create an AP. TM_MS < TM_acceptable (", TM_MS, "<", TM_acceptable)
			destintion_servicename := strings.Split(fmt.Sprintf("%v", victimsservicesNames), "@")
			for i := 0; i < len(destintion_servicename)-1; i++ {
				log.Println("-------------------------------------------------------------------------------------------", MS, "---------------------------------------------------------", destintion_servicename[i])
				var tem_TM_MS = TM_MS
				if destintion_servicename[i] != "\"" {

					// reduce the ops for each service based on each service price
					s_object := getS(strings.Split(destintion_servicename[i], ":")[0])
					//getAP_adaptation_Confidentiality_Integrity_Availability_cost(getCIA_obj[0], getCIA_obj[4], getCIA_obj[2])
					//log.Println("CIA value for", strings.Split(destintion_servicename[i], ":")[0], "=", getCIA_obj)

					//getAP_adaptation_Confidentiality := getAP_adaptation_Confidentiality(getCIA_obj[0])
					getAP_adaptation_map := getConfigMap(s_object, IsItgRPC_)

					// OSCAL get from getAP_adaptation_map the Get price, Post price, PUT price, DELETE price
					getPriceGET := getAP_adaptation_map["GET"]
					getPricePOST := getAP_adaptation_map["POST"]
					getPricePUT := getAP_adaptation_map["PUT"]
					getPriceDELETE := getAP_adaptation_map["DELETE"]

					// OSCAL below is not needed due to getAP_adaptation_Confidentiality will be named as getAP_adaptation_Confidentiality_Integrity_Availability_cost
					//getAP_adaptation_Integrity := getAP_adaptation_Integrity(getCIA_obj[4])
					//log.Println("getAP_adaptation_Integrity", getAP_adaptation_Integrity)

					// OSCAL below is not needed due to getAP_adaptation_Confidentiality will be named as getAP_adaptation_Confidentiality_Integrity_Availability_cost
					//getAP_adaptation_Availability := getAP_adaptation_Availability(getCIA_obj[2])
					//log.Println("getAP_adaptation_Availability", getAP_adaptation_Availability)

					// OSCAL below is not needed due to getAP_adaptation_Confidentiality will be named as getAP_adaptation_Confidentiality_Integrity_Availability_cost
					//getHighestPriceGET := getHighestPrice(getAP_adaptation_Confidentiality["GET"], getAP_adaptation_Integrity["GET"], getAP_adaptation_Availability["GET"])
					//getHighestPricePOST := getHighestPrice(getAP_adaptation_Confidentiality["POST"], getAP_adaptation_Integrity["POST"], getAP_adaptation_Availability["POST"])
					//getHighestPricePUT := getHighestPrice(getAP_adaptation_Confidentiality["PUT"], getAP_adaptation_Integrity["PUT"], getAP_adaptation_Availability["PUT"])
					//getHighestPriceDELETE := getHighestPrice(getAP_adaptation_Confidentiality["DELETE"], getAP_adaptation_Integrity["DELETE"], getAP_adaptation_Availability["DELETE"])
					//log.Println("getHighestPriceGET:", getHighestPriceGET)
					//log.Println("getHighestPricePOST:", getHighestPricePOST)
					//log.Println("getHighestPricePUT:", getHighestPricePUT)
					//log.Println("getHighestPriceDELETE:", getHighestPriceDELETE)

					// Convernt the pricess to float64 then Order them to psend TM_MS to purchase Ops that has highest price
					var P_get_float, _ = strconv.ParseFloat(strings.TrimSpace(getPriceGET), 64)
					var P_post_float, _ = strconv.ParseFloat(strings.TrimSpace(getPricePOST), 64)
					var P_put_float, _ = strconv.ParseFloat(strings.TrimSpace(getPricePUT), 64)
					var P_delete_float, _ = strconv.ParseFloat(strings.TrimSpace(getPriceDELETE), 64)

					order_prices := []struct {
						ops_name string
						price    float64
					}{
						{"GET", P_get_float},
						{"POST", P_post_float},
						{"PUT", P_put_float},
						{"DELETE", P_delete_float},
					}

					// Sort by biggest value, keeping original order or equal elements.
					sort.SliceStable(order_prices, func(i, j int) bool {
						return order_prices[i].price > order_prices[j].price
					})
					log.Println("RAdAC function(): Handling the adaptation for service:", destintion_servicename[i], " that has CRUD+O order by highest to lowest: ", order_prices)

					new_ops := []string{}

					for j := 0; j < len(order_prices); j++ {

						//fmt.Println("strings.Split(destintion_servicename[i], \":\")[1]=", strings.Split(destintion_servicename[i], ":")[1])
						//fmt.Println(" order_prices[i].ops_name=", order_prices[j].ops_name)

						if strings.Contains(strings.Split(destintion_servicename[i], ":")[1], order_prices[j].ops_name) {
							log.Println("Found the ops:", order_prices[j].ops_name, " in:", strings.Split(destintion_servicename[i], ":")[1])
							log.Println("TM_MS=", tem_TM_MS, " and the price for the ops:", order_prices[j].ops_name, " is equals=", order_prices[j].price)

							if tem_TM_MS >= order_prices[j].price {
								log.Println("Yes TM_MS can purachse this ops. tem_TM_MS >= order_prices[j].price, ")

								// Go a head and purach this
								new_ops = append(new_ops, order_prices[j].ops_name)

								// decrease TM by the above price
								tem_TM_MS = tem_TM_MS - order_prices[j].price
								log.Println("New TM_MS after decreasing the prices of (", order_prices[j].ops_name, ")=", tem_TM_MS)

							} else {
								log.Println("No enough TM points can not purache this ops")
								log.Println("Remove this privilege")

								// remove this privilege
							}
						}
					}
					log.Println("Before RAdAC ops:", strings.Split(destintion_servicename[i], ":")[1])
					log.Println("After RAdAC new_ops:", new_ops)

					// Delete AP
					log.Println("Istio: Delete AP:", "case2-"+strings.Replace(MS, "\"", "", -1)+"-toward-"+strings.Split(destintion_servicename[i], ":")[0])
					deleteAP("allow-only-" + strings.Replace(MS, "\"", "", -1) + "-toward-" + strings.Split(destintion_servicename[i], ":")[0])
					adaptivecase(strings.Replace(MS, "\"", "", -1), new_ops, strings.Split(destintion_servicename[i], ":")[0])
					var RAdAC_CRURD = ""

					RAdAC_CRURD = RAdAC_CRURD + strings.Split(destintion_servicename[i], ":")[0] + ":" + strings.Join(new_ops, "") + "@"
					log.Println("C.get() before=", c.Items())

					//c.Set(MS, RAdAC_CRURD+"\"", cache.DefaultExpiration)
					c.Set("\""+MS+"\"", RAdAC_CRURD+"\"", cache.DefaultExpiration)

					log.Println("I just sat the cachse as:", RAdAC_CRURD)
					log.Println("C.get() after=", c.Items())
					// Re create it usign the new new_ops
				} else {
					// do nothing
					log.Println("The end. Nor more services are available.")
				}
			}
		}
	}
	// Get CRUD functions
	log.Println("End ±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±± RAdAC ±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±±")

}

// A supportive method.
func service_and_theirCRUD_grpc(getmeList string, MS string) map[string]string {
	fmt.Println("----------------------------- getVitimService () ---------- start")

	//log.Println("################## APG Function: service_and_theirCRUD_grpc() ################## start")
	service_and_theirCRUD_grpc := make(map[string]string)
	//  s1:GETPOSTDELETEPUT@s10:GETPOST@s2:GET@"
	list_of_Service_with_CRUD := strings.Split(getmeList, "@")
	for i := range list_of_Service_with_CRUD {
		destintion_servicename := strings.Split(list_of_Service_with_CRUD[i], ":")
		//log.Println("MS=", MS, " has access toward services:", destintion_servicename)
		//log.Println("size of destintion_servicename=", len(destintion_servicename))
		if len(destintion_servicename) > 1 {

			//log.Println("MS=", MS, " has CRUD toward:", list_of_Service_with_CRUD[i])
			//service_and_theirCRUD[MS] = append(x["key"], "value")
			//if strings.Join(destintion_servicename, ", ") != "\"" {
			//listofdes = listofdes + destintion_servicename[0]
			//log.Println("listofdes=", listofdes)
			if len(destintion_servicename[1]) > 2 {
				fmt.Println("-----------  there are some functions. Assign to the list as no connections----------")
				service_and_theirCRUD_grpc[destintion_servicename[0]] = destintion_servicename[1]

			} else {
				// there are no REST/gRPC connections
				fmt.Println("----------- There are no REST/gRPC connections. Do not assign it to the list----------")
			}

			//ops_names = ops_names + destintion_servicename[1]
			//log.Println("ops_names=", ops_names)
			// service_and_theirCRUD[vs.GetName()] = vs.Spec.Ports[0].Port
			//log.Println("service_and_theirCRUD=", service_and_theirCRUD)
		}
		//log.Println("at the end: service_and_theirCRUD=", service_and_theirCRUD)
		//}
	}
	fmt.Println("---------------- service_and_theirCRUD_grpc=", service_and_theirCRUD_grpc)

	fmt.Println("----------------------------- service_and_theirCRUD_grpc () ---------- end")

	return service_and_theirCRUD_grpc
}

// A supportive method. Google I got this: https://stackoverflow.com/questions/19374219/how-to-find-the-difference-between-two-slices-of-strings
func difference(slice1 []string, slice2 []string, SS string) []string {
	diffStr := []string{}
	m := map[string]int{}
	log.Println("differencedifferencedifferencedifferencedifferencedifferencedifferencedifferencedifference")
	log.Println("")

	for _, s1Val := range slice1 {
		log.Println("s1Val=", s1Val)
		m[s1Val] = 1
	}
	for _, s2Val := range slice2 {
		log.Println("s2Val=", s2Val)

		m[s2Val] = m[s2Val] + 1
	}

	for mKey, mVal := range m {
		log.Println("mVal=", mVal)

		if mVal == 1 && mKey != SS {
			log.Println("diffStr=", diffStr)
			log.Println("mKey=", mKey)

			diffStr = append(diffStr, mKey)
		} else {
			log.Println("SS=", SS, " and should not be incldued to the list")
		}

	}

	return diffStr
}

// A supportive method: Get assigned microservice service sensitivity
func getS(serviceName string) string {
	namespace := apiv1.NamespaceDefault
	config := getConneciton(flag_)
	clientset, err := kubernetes.NewForConfig(config)

	pods, _ := clientset.CoreV1().Pods(namespace).List(context.TODO(), metav1.ListOptions{})

	if err != nil {
		log.Fatalf("Failed to get K8s client in getS() method %s namespace: %s", "default", err)
	}
	//CIA := []string{}
	var S string

	for i := range pods.Items {
		po := pods.Items[i]
		if po.Labels["app"] == serviceName {
			S = po.Labels["s"]
		}
	}
	return S
}

// A to get if a deployed microservice is a isItgRPC or a REST. This happen by check if it has the word gRPC OR the last line is not empty (request paths)
func IsItgRPC(MS string) bool {
	var isItgRPC = false
	data, err := ioutil.ReadFile("Metrics.csv")
	if err != nil {
		fmt.Println(err)
	}
	lines := strings.Split(string(data), "\n")

	for _, line := range lines {
		if strings.Contains(line, "Microservice_name") {
		} else {
			regexp := regexp.MustCompile(`"([^"]*)"`)
			matches := regexp.FindAllStringSubmatch(line, -1)

			// Extract only the captured groups (values inside quotes)
			var values []string
			for _, match := range matches {
				values = append(values, match[1])
			}

			each_line := strings.Split(line, ",")

			if each_line[0] == MS {
				if strings.Contains(strings.Join(each_line, ", "), "grpc") || len(values[7]) > 3 {
					isItgRPC = true
				} else {
					isItgRPC = false
				}

			}

		}

	}
	/*

		log.Println("isItgRPC=====", isItgRPC)
	*/
	return isItgRPC
}
