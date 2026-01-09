namespace AuthServer.Main.Models;
public class ResultModel<T>
{
    public int Status { get; set; }
    public string Message { get; set; }
    public T Data { get; set; }
}
