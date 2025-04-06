package main

import (
	context "context"
	"fmt"
	"github.com/gin-gonic/gin"
	securityv1beta1 "istio.io/api/security/v1beta1"
	"istio.io/client-go/pkg/apis/security/v1beta1"
	versionedclient "istio.io/client-go/pkg/clientset/versioned"
	apiv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"k8s.io/client-go/rest"
	"log"
	"net/http"
	"reflect"
	"strings"
)

func main() {

	router := gin.Default()
	router.GET("/create", create)
	//router.Run("localhost:9770")
	router.Run(":9770")

}
func createAuthorizationPolicy(AuthorizationPolicyName string, option string, trustscore, maliciousservice string, victimsservices string) error {

	// Enable for InClusterConfig

	config, err := rest.InClusterConfig()
	if err != nil {
		panic(err.Error())
	}
	clientset, err := kubernetes.NewForConfig(config)

	// Enable for OutClusterConfig
	/*
		var kubeconfig *string
		flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
		if home := homedir.HomeDir(); home != "" {
			kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
		} else {
			kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
		}
		flag.Parse()
		//fmt.Println("kubeconfig====", kubeconfig)
		config, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
		clientset, err := kubernetes.NewForConfig(config)
	*/

	/////// DONE
	services, _ := clientset.CoreV1().Services("").List(context.TODO(), metav1.ListOptions{})
	dictionaryEnSv := make(map[string]int32)

	if err != nil {
		log.Fatalf("Failed to get VirtualService in %s namespace: %s", "default", err)
	}
	for i := range services.Items {
		vs := services.Items[i]
		//log.Println("services.Ports()=", vs.Spec.Ports)
		log.Println("services.NodePort()=", vs.Spec.Ports[0].NodePort)

		dictionaryEnSv[vs.GetName()] = vs.Spec.Ports[0].NodePort
	}

	log.Println("ports >>>>>>", dictionaryEnSv)

	victimsservicesNames := strings.Split(victimsservices, ",")
	portslist := []string{}
	ops := []string{}
	log.Println("option >>>>>>>>>>_________>>>", option)

	switch option {
	case "1":
		ops = append(ops, "POST", "PUT", "DELETE")
	case "2":
		ops = append(ops, "PUT", "DELETE")
	case "3":
		ops = append(ops, "DELETE")
	case "4":
		ops = append(ops, "")
	}
	log.Println("ops >>>>>>>>>>_________>>>", ops)

	sourcelist := []string{}
	sourcelist = append(sourcelist, fmt.Sprint(strings.ToLower("cluster.local/ns/default/sa/"+maliciousservice)))
	log.Println("sourcelist >>>>>>>>>>_________>>>", sourcelist)

	for i := 0; i < len(victimsservicesNames); i++ {
		nametmp := victimsservicesNames[i]
		log.Println("Is it correct:", nametmp)
		log.Println("Is it correct:", dictionaryEnSv[strings.ToLower(nametmp)])
		portslist = append(portslist, fmt.Sprint(dictionaryEnSv[strings.ToLower(nametmp)]))

		log.Println("Port for service %s is equals=", victimsservicesNames[i], dictionaryEnSv[strings.ToLower(nametmp)])
	}

	log.Println("portslist >>>>>>", portslist)

	// Create AuthorizationPolicy
	b := &v1beta1.AuthorizationPolicy{}
	b.SetName("allowtest")
	//policydata := map[string]string{
	//	"action": "ALLOW",
	//}
	apname := fmt.Sprintf("%s%s%s%s%s", AuthorizationPolicyName, "-",
		trustscore, "-", option)
	deployment := &v1beta1.AuthorizationPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: apname +
				"",
			Namespace: "default",
		},
		Spec: securityv1beta1.AuthorizationPolicy{
			//Selector: &v1beta2.WorkloadSelector{
			//	MatchLabels: map[string]string{
			//		"app": maliciousservice,
			//	},
			//	},
			Action: securityv1beta1.AuthorizationPolicy_DENY,
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
	icc, err := versionedclient.NewForConfig(config)

	fmt.Println("type 2nd = ", reflect.TypeOf(b))
	fmt.Println("deployment = ", deployment)

	autCreate, err := icc.SecurityV1beta1().AuthorizationPolicies("default").Create(
		context.TODO(),
		deployment,
		metav1.CreateOptions{},
	)
	if err != nil {
		return fmt.Errorf("Failed to create AuthorizationPolicies in namespace %s", err)
	}

	return fmt.Errorf("var1 = ", autCreate.GetNamespace())

}
func getports() map[string]int32 {

	namespace := apiv1.NamespaceDefault

	// Enable for InClusterConfig

	config, err := rest.InClusterConfig()
	if err != nil {
		panic(err.Error())
	}
	clientset, err := kubernetes.NewForConfig(config)

	// Enable for OutClusterConfig
	/*
		var kubeconfig *string
		flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
		if home := homedir.HomeDir(); home != "" {
			kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
		} else {
			kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
		}
		flag.Parse()
		//fmt.Println("kubeconfig====", kubeconfig)
		config, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
		clientset, err := kubernetes.NewForConfig(config)
	*/
	if err != nil {
		panic(err.Error())
	}
	services, _ := clientset.CoreV1().Services("").List(context.TODO(), metav1.ListOptions{})
	dictionaryEnSv := make(map[string]int32)

	if err != nil {
		log.Fatalf("Failed to get VirtualService in %s namespace: %s", namespace, err)

	}
	for i := range services.Items {
		vs := services.Items[i]
		//log.Println("services.Ports()=", vs.Spec.Ports)
		//log.Println("services.GetName()=", vs.GetName())
		//log.Println("services port ()=", vs.Spec.Ports[0].Port)
		dictionaryEnSv[vs.GetName()] = vs.Spec.Ports[0].Port
	}

	return dictionaryEnSv

}
func create(con *gin.Context) {
	//http://localhost services.NodePort():1025/create?trustscore=00&maliciousservice=emailserivce&policyname=test12

	log.Println(con.Request.URL.Query())
	parameters := con.Request.URL.Query()
	log.Println("maliciousservice=", parameters["maliciousservice"])
	log.Println("policyname=", parameters["policyname"])
	log.Println("trustscore=", parameters["trustscore"])
	log.Println("victimsservices=", parameters["victimsservices"])
	log.Println("option=", parameters["option"])

	log.Println("Calling the method:createAuthorizationPolicy")
	createAuthorizationPolicy(strings.Join(parameters["policyname"], ""), strings.Join(parameters["option"], ""), strings.Join(parameters["trustscore"], ""), strings.Join(parameters["maliciousservice"], ""), strings.Join(parameters["victimsservices"], ""))
	//con.IndentedJSON(http.StatusNotFound, gin.H{"message": "AuthorizationPolicy is created"})
	//return (con.IndentedJSON(http.StatusOK, status)
	con.IndentedJSON(http.StatusOK, gin.H{"message": "AuthorizationPolicy was created"})

}
