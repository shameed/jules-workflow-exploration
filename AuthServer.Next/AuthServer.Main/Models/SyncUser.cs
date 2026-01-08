namespace AuthServer.Main.Models
{
    public class SyncUser
    {
        public long UserPK { get; set; }
        public string UserName { get; set; }
        public int ActiveDays { get; set; }
        public int ResetDays { get; set; }
        public int Status { get; set; }
        public string Message { get; set; }
    }
}
