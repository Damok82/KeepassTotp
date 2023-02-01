using KeePass.Plugins;
using KeePass.UI;
using KeePassLib;
using OtpNet;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Drawing;
using System.Windows.Forms;

namespace KeePassPlugin2FA
{
    // https://keepass.info/help/v2_dev/plg_index.html
    // ReSharper disable once UnusedType.Global
    // ReSharper disable once InconsistentNaming
    public class KeePassPlugin2FAExt : Plugin
    {
        private const string TwoFactorStringPattern = "2FA";
        private const Keys Shortcut = Keys.Control | Keys.T;

        private IPluginHost _host;
        private readonly List<ToolStripMenuItem> _toolStripMenuItems = new List<ToolStripMenuItem>(3);

        public override bool Initialize(IPluginHost host)
        {
            Logging.LogMessage($"{nameof(Initialize)}()");

            if (null == host)
            {
                Logging.LogMessage($"Parameter '{nameof(host)}' is null. Aborting initialization.");
                return false;
            }

            _host = host;
            _host.MainWindow.EntryContextMenu.Opening += EntryContextMenuOpening;
            Logging.LogMessage("Initialization completed.");

            return true;
        }

        public override void Terminate()
        {
            Logging.LogMessage($"{nameof(Terminate)}()");
            _host.MainWindow.EntryContextMenu.Opening -= EntryContextMenuOpening;
            Logging.LogMessage("Termination completed.");
        }

        public void EntryContextMenuOpening(object sender, CancelEventArgs cancelEventArguments)
        {
            Logging.LogMessage($"{nameof(EntryContextMenuOpening)}()");

            if (!(sender is CustomContextMenuStripEx))
            {
                Logging.LogMessage($"Sender is not an instance of '{typeof(CustomContextMenuStripEx).FullName}' but '{sender.GetType().FullName}'.");

                return;
            }


            bool is2FaEntry = IsEntrySelected(out PwEntry pwEntry);
            if (is2FaEntry)
            {
                is2FaEntry &= Is2FaEntry(pwEntry);
            }

            foreach (ToolStripMenuItem toolStripMenuItem in _toolStripMenuItems)
            {
                toolStripMenuItem.Enabled = is2FaEntry;
            }
        }

        private bool IsEntrySelected(out PwEntry pwEntry)
        {
            pwEntry = _host.MainWindow.GetSelectedEntry(true);

            return (null != pwEntry);
        }

        public override ToolStripMenuItem GetMenuItem(PluginMenuType pluginMenuType)
        {
            Logging.LogMessage($"{nameof(GetMenuItem)}()");

            if (PluginMenuType.Entry != pluginMenuType)
            {
                Logging.LogMessage($"Skipping plugin menu item type '{pluginMenuType}'.");

                return null;
            }

            string toolStripMenuItemName = Properties.UiResources.PluginMenuTypeEntryDisplayName;
            Image pluginMenuEntryImage = _host.MainWindow.ClientIcons.Images[(int)PwIcon.Clock];
            Logging.LogMessage("Creating a new menu item ...");
            ToolStripMenuItem toolStripMenuItem = new ToolStripMenuItem(toolStripMenuItemName, pluginMenuEntryImage, KeePassPlugin2FAExtOnClickEntryHandler, Shortcut) { Enabled = false };

            Logging.LogMessage($"Adding plugin menu item '{toolStripMenuItemName}' ...");
            _toolStripMenuItems.Add(toolStripMenuItem);
            Logging.LogMessage("Plugin menu item added.");

            return toolStripMenuItem;
        }

        public void KeePassPlugin2FAExtOnClickEntryHandler(object sender, EventArgs eventArgs)
        {
            Logging.LogMessage($"{nameof(KeePassPlugin2FAExtOnClickEntryHandler)}()");

            if (!IsEntrySelected(out PwEntry pwEntry))
            {
                return;
            }

            string totpSecret = pwEntry.Strings.Get("Password")?.ReadString()?.Replace(" ", string.Empty);
            if (null == totpSecret)
            {
                return;
            }

            string twoFactorCode = GenerateTwoFactorCode(totpSecret);
            if (string.IsNullOrEmpty(twoFactorCode))
            {
                Logging.LogMessage("Could not gernerate a 2FA token.");

                return;
            }

            if (KeePass.Util.ClipboardUtil.Copy(twoFactorCode, false, false, null, null, IntPtr.Zero))
            {
                _host.MainWindow.StartClipboardCountdown();
            }
        }

        private static bool Is2FaEntry(PwEntry pwEntry)
        {
            Logging.LogMessage($"{nameof(Is2FaEntry)}()");

            if (null == pwEntry)
            {
                throw new ArgumentNullException(nameof(pwEntry));
            }

            string title = pwEntry.Strings.Get("Title")?.ReadString();
            if (string.IsNullOrEmpty(title))
            {
                return false;
            }

            if (!title.ToLower().Contains(TwoFactorStringPattern.ToLower()))
            {
                Logging.LogMessage($"Entry's title '{pwEntry.Strings.Get("Title")?.ReadString() ?? "<empty title>"}' ({pwEntry.Uuid.ToHexString()}) does contain the string '{TwoFactorStringPattern}'.");

                return false;
            }

            Logging.LogMessage($"Entry's title '{pwEntry.Strings.Get("Title")?.ReadString() ?? "<empty title>"}' ({pwEntry.Uuid.ToHexString()}) does contain the string '{TwoFactorStringPattern}'.");

            return true;
        }

        private string GenerateTwoFactorCode(string totpSecret)
        {
            Logging.LogMessage($"{nameof(GenerateTwoFactorCode)}()");

            try
            {
                Totp totp = new Totp(Base32Encoding.ToBytes(totpSecret));

                return totp.ComputeTotp();
            }
            catch (Exception e)
            {
                bool isLogActivated = Logging.IsActivated;
                try
                {
                    Logging.IsActivated = true;
                    Logging.LogMessage("An exception occurred:");
                    Logging.LogMessage(e.GetType().FullName);
                    Logging.LogMessage(e.Message);
                    Logging.LogMessage(e.StackTrace);
                }
                finally
                {
                    Logging.IsActivated = isLogActivated;
                }

                string errorMesage = $"An exception occurred:\r\n'{e.GetType().FullName}'\r\n\r\n{e.Message}";
                MessageBox.Show(_host.MainWindow, errorMesage, "An exception occurred", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }

            return null;
        }
    }
}
