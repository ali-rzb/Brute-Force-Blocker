using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics.Eventing.Reader;
using System.Drawing;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Brute_Force_Blocker
{
    #region Log Details
    //4624 : 
    //4625 : An account failed to log on.

    //4634 : This event is generated when a logon session is destroyed.

    //4648 : a process attempts to log on an account by explicitly specifying that account’s credentials.

    //4672 : Special privileges assigned to new logon.

    //4732 : A member was added to a security-enabled local group.
    //4733 : A member was removed from a security-enabled local group.

    //4776 : domain controller (DC) attempts to validate the credentials of an account using NTLM over Kerberos

    //4798 : A user's local group membership was enumerated.
    //4799 : A security-enabled local group membership was enumerated.

    //5061 : Cryptographic operation.
    //5379 : Credential Manager credentials were read.

    //6272 : The network policy server granted access to a user. 
    //6273 : Network Policy Server denied access to a user. 
    #endregion

    public partial class Form1 : Form
    {
        private List<EventRecord> FailedLogins;
        private EventLogQuery evntquery;
        private EventLogReader reader;
        private EventRecord eventInstance;
        private Dictionary<string, string> IPAddresses;
        private double counter;

        private Dictionary<string, Tuple<int, string>> IPSort;
        public async Task LoadData()
        {
            Block.Enabled = false;
            BlockAll.Enabled = false;
            Refresh.Enabled = false;
            Unblock.Enabled = false;
            
            blockedIpAddresses.Items.Clear();
            blockedIpAddresses.Items.Add(MyStringFormat("IP", "Country"));
            blockedIpAddresses.Items.Add("");

            IPAddresses = new Dictionary<string, string>();
            foreach (var IP in FirewallClass.GetIPAddress())
            {
                IPAddresses[IP] = (await IPUtil.GetIPInfoAsync(IP)).Country;
                blockedIpAddresses.Items.Add(MyStringFormat(IP, IPAddresses[IP]));
            }

            FailedLogins = new List<EventRecord>();

            evntquery = new EventLogQuery("Security", PathType.LogName, string.Format("*", "Security")) { Session = new EventLogSession() };
            reader = new EventLogReader(evntquery);
            //string exportedLogFilePath = @"C:\Users\Ali\Downloads\ExportedSecurity.evtx";
            //reader = new EventLogReader(new EventLogQuery(exportedLogFilePath, PathType.FilePath));
            eventInstance = reader.ReadEvent();
            IPSort = new Dictionary<string, Tuple<int, string>>();
            counter = 0;
            

            int step = 0;
            int stepPerBreath = 100;
            for (; null != eventInstance; eventInstance = reader.ReadEvent())
            {
                LoadingLabel.Text = (++counter).ToString();
                step++;
                if (step >= stepPerBreath || step == 0)
                {
                    await Task.Delay(1);
                    step = 1;
                }
                if (eventInstance.Id == 4625)
                {
                    FailedLogins.Add(eventInstance);
                    var ip = eventInstance.Properties[19].Value.ToString();
                    if (!(ip.StartsWith("10.10.10.") || ip.StartsWith("192.168.") || ip.StartsWith("127.0.0.1")) && IsIPv4Address(ip))
                    {
                        if (!IPSort.Keys.Contains(ip))
                        {
                            var Location = await IPUtil.GetIPInfoAsync(ip);
                            IPSort[ip] = new Tuple<int, string>(1, Location.Country);
                        }
                        else
                        {
                            IPSort[ip] = new Tuple<int, string>(IPSort[ip].Item1 + 1, IPSort[ip].Item2);
                        }
                        ipListBox.Items.Clear();
                        ipListBox.Items.Add(MyStringFormat("IP", "Total", "Country"));
                        ipListBox.Items.Add("");
                        for (int i = 0; i < IPSort.Count; i++)
                        {
                            if (!IPAddresses.Keys.Contains(IPSort.Keys.ElementAt(i)))
                            {
                                string formattedIpAddress = MyStringFormat(IPSort.Keys.ElementAt(i), IPSort[IPSort.Keys.ElementAt(i)].Item1.ToString(), IPSort[IPSort.Keys.ElementAt(i)].Item2);
                                ipListBox.Items.Add(formattedIpAddress);
                            }
                        }
                    }
                }
            }
            LoadingLabel.Text = "Loaded!";
            Block.Enabled = true;
            BlockAll.Enabled = true;
            Refresh.Enabled = true;
            Unblock.Enabled = true;
        }
        public void RefreshDateOrder()
        {
            blockedIpAddresses.Invoke(new Action(() =>
            {
                var firewallIPList = FirewallClass.GetIPAddress();
                blockedIpAddresses.Items.Clear();
                blockedIpAddresses.Items.Add(MyStringFormat("IP", "Country"));
                blockedIpAddresses.Items.Add("");

                foreach (var IP in firewallIPList)
                {
                    if (!IPAddresses.ContainsKey(IP))
                    {
                        IPAddresses[IP] = Task.Run(() => IPUtil.GetIPInfoAsync(IP)).Result.Country;
                    }
                    blockedIpAddresses.Items.Add(MyStringFormat(IP, IPAddresses[IP]));

                }
                var ipsToRemove = IPAddresses.Keys.Except(firewallIPList).ToList();
                foreach (var IP in ipsToRemove)
                {
                    IPAddresses.Remove(IP);
                }
            }));

            ipListBox.Invoke(new Action(() =>
            {
                ipListBox.Items.Clear();
                ipListBox.Items.Add(MyStringFormat("IP", "Total", "Country"));
                ipListBox.Items.Add("");

                for (int i = 0; i < IPSort.Count; i++)
                {
                    var ip = IPSort.Keys.ElementAt(i);
                    if (!IPAddresses.Keys.Contains(ip))
                    {
                        string formattedIpAddress = MyStringFormat(ip, IPSort[ip].Item1.ToString(), IPSort[ip].Item2);
                        ipListBox.Items.Add(formattedIpAddress);
                    }
                }
            }));
        }


        public Form1()
        {
            InitializeComponent();
            titleLabel.Text = "List of IP Addresses";
            FirewallClass.CreateFirewallRule();
            this.Shown += MainForm_Shown;

        }

        private async void MainForm_Shown(object sender, EventArgs e)
        {
            try
            {
                await LoadData();
            }
            catch (UnauthorizedAccessException)
            {
                MessageBox.Show("Please run the program as an administrator.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                Environment.Exit(1);
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message + ex.StackTrace, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void Form1_Load(object sender, EventArgs e)
        {

        }

        private string MyStringFormat(params string[] args)
        {
            var output = "";
            for (int i = 0; i < args.Length; i++)
            {
                var item = !string.IsNullOrEmpty(args[i]) ? args[i] : new String(' ', 16);
                if(item.Length<=16)
                    output += $"{item}{new String(' ', 16 - item.Length)}\t";
                else
                    output += $"{item}\t";
            }
            return output;
        }

        private void Block_Click(object sender, EventArgs e)
        {
            //var selectedIP = "31.31.31.31";
            //FirewallClass.AddIPAddressToRule(new string[1] { selectedIP });
            //RefreshDateOrder();

            if (ipListBox.SelectedItem == null)
            {
                MessageBox.Show("Please select and ip to block!");
            }
            else
            {
                var selectedIP = ipListBox.SelectedItem.ToString().Split('\t')[0].Trim();
                FirewallClass.AddIPAddressToRule(new string[1] { selectedIP });
                Task.Run(() => RefreshDateOrder());
            }
        }
        private void Unblock_Click(object sender, EventArgs e)
        {
            if (blockedIpAddresses.SelectedItem == null)
            {
                MessageBox.Show("Please select and ip to unblock!");
            }
            else
            {
                var selectedIP = blockedIpAddresses.SelectedItem.ToString().Split('\t')[0].Trim();
                FirewallClass.RemoveIPAddressFromRule(new string[1] { selectedIP });
                Task.Run(() => RefreshDateOrder());
            }
        }
        private void Refresh_Click(object sender, EventArgs e)
        {
            Task.Run(() => RefreshDateOrder());
        }

        private void BlockAll_Click(object sender, EventArgs e)
        {
            foreach (var item in ipListBox.Items)
            {
                try
                {
                    var selectedIP = item.ToString().Split('\t')[0].Trim();
                    if (IsIPv4Address(selectedIP))
                    {
                        FirewallClass.AddIPAddressToRule(new string[1] { selectedIP });
                    }
                }
                catch { }
            }
            Task.Run(() =>  RefreshDateOrder());
        }

        static bool IsIPv4Address(string input)
        {
            // Define the IPv4 address pattern
            string ipv4Pattern = @"^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|[0-1]?[0-9]?[0-9])){3}$";

            // Check if the input string matches the IPv4 pattern
            return Regex.IsMatch(input, ipv4Pattern);
        }
    }
}
