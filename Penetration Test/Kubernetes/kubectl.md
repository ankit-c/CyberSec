#### List all the NAMESPACES.

```kubectl get namespaces -o wide```

#### List all the pods inside the NAMESPACE.

```kubectl top pod --namespace=<NAMESPACE>```

#### Commands

```kubectl get pods```: Check pod status.

```kubectl get nodes```: Check node status.

```kubectl get namespaces```: List namespaces.

```kubectl get deployments```: View deployment status.

```kubectl get services```: List services.

```kubectl get configmaps```: List configmaps.

```kubectl get secrets```: List secrets.

```kubectl get events```: Monitor cluster-wide events.



```kubectl describe pod <pod-name>```: Detailed pod info.

```kubectl describe node <node-name>```: Detailed node info.

```kubectl describe namespace <namespace-name>```: Detailed namespace info.

```kubectl describe service <service-name>```: Detailed service info.

```kubectl describe configmap <configmap-name>```: Detailed configmap info.

```kubectl describe secret <secret-name>```: Detailed secret info.


```kubectl logs <pod-name>```: Retrieve pod logs.

```kubectl exec -it <pod-name> -- <command>```: Execute commands in pods.

```kubectl top <resource>```: Monitor resource usage.

```kubectl rollout status <deployment-name>```: Check deployment status.

```kubectl port-forward <pod-name> <local-port>:<pod-port>```: Expose pod ports locally.
