﻿namespace Brute_Force_Blocker
{
    partial class Form1
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(Form1));
            this.ipListBox = new System.Windows.Forms.ListBox();
            this.titleLabel = new System.Windows.Forms.Label();
            this.blockedIpAddresses = new System.Windows.Forms.ListBox();
            this.Block = new System.Windows.Forms.Button();
            this.Unblock = new System.Windows.Forms.Button();
            this.Refresh = new System.Windows.Forms.Button();
            this.label1 = new System.Windows.Forms.Label();
            this.LoadingLabel = new System.Windows.Forms.Label();
            this.BlockAll = new System.Windows.Forms.Button();
            this.label2 = new System.Windows.Forms.Label();
            this.SuspendLayout();
            // 
            // ipListBox
            // 
            this.ipListBox.ColumnWidth = 500;
            this.ipListBox.Font = new System.Drawing.Font("Roboto Condensed", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.ipListBox.FormattingEnabled = true;
            this.ipListBox.ItemHeight = 19;
            this.ipListBox.Location = new System.Drawing.Point(10, 25);
            this.ipListBox.Margin = new System.Windows.Forms.Padding(2, 3, 2, 3);
            this.ipListBox.Name = "ipListBox";
            this.ipListBox.Size = new System.Drawing.Size(447, 612);
            this.ipListBox.TabIndex = 0;
            // 
            // titleLabel
            // 
            this.titleLabel.AutoSize = true;
            this.titleLabel.Location = new System.Drawing.Point(10, 9);
            this.titleLabel.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.titleLabel.Name = "titleLabel";
            this.titleLabel.Size = new System.Drawing.Size(33, 13);
            this.titleLabel.TabIndex = 1;
            this.titleLabel.Text = "label1";
            // 
            // blockedIpAddresses
            // 
            this.blockedIpAddresses.Font = new System.Drawing.Font("Roboto Condensed", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.blockedIpAddresses.FormattingEnabled = true;
            this.blockedIpAddresses.ItemHeight = 19;
            this.blockedIpAddresses.Location = new System.Drawing.Point(566, 25);
            this.blockedIpAddresses.Margin = new System.Windows.Forms.Padding(2, 3, 2, 3);
            this.blockedIpAddresses.Name = "blockedIpAddresses";
            this.blockedIpAddresses.Size = new System.Drawing.Size(339, 612);
            this.blockedIpAddresses.TabIndex = 2;
            // 
            // Block
            // 
            this.Block.Font = new System.Drawing.Font("Roboto Condensed", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.Block.Location = new System.Drawing.Point(461, 25);
            this.Block.Margin = new System.Windows.Forms.Padding(2, 3, 2, 3);
            this.Block.Name = "Block";
            this.Block.Size = new System.Drawing.Size(100, 52);
            this.Block.TabIndex = 3;
            this.Block.Text = "Block";
            this.Block.UseVisualStyleBackColor = true;
            this.Block.Click += new System.EventHandler(this.Block_Click);
            // 
            // Unblock
            // 
            this.Unblock.Font = new System.Drawing.Font("Roboto Condensed", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.Unblock.Location = new System.Drawing.Point(462, 527);
            this.Unblock.Margin = new System.Windows.Forms.Padding(2, 3, 2, 3);
            this.Unblock.Name = "Unblock";
            this.Unblock.Size = new System.Drawing.Size(99, 52);
            this.Unblock.TabIndex = 4;
            this.Unblock.Text = "Unblock";
            this.Unblock.UseVisualStyleBackColor = true;
            this.Unblock.Click += new System.EventHandler(this.Unblock_Click);
            // 
            // Refresh
            // 
            this.Refresh.Font = new System.Drawing.Font("Roboto Condensed", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.Refresh.Location = new System.Drawing.Point(462, 585);
            this.Refresh.Name = "Refresh";
            this.Refresh.Size = new System.Drawing.Size(99, 52);
            this.Refresh.TabIndex = 5;
            this.Refresh.Text = "Refresh";
            this.Refresh.UseVisualStyleBackColor = true;
            this.Refresh.Click += new System.EventHandler(this.Refresh_Click);
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Font = new System.Drawing.Font("Roboto Condensed", 9.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label1.Location = new System.Drawing.Point(477, 492);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(60, 15);
            this.label1.TabIndex = 6;
            this.label1.Text = "  Ali Rzb.   ";
            this.label1.TextAlign = System.Drawing.ContentAlignment.MiddleCenter;
            // 
            // LoadingLabel
            // 
            this.LoadingLabel.Anchor = System.Windows.Forms.AnchorStyles.Top;
            this.LoadingLabel.AutoSize = true;
            this.LoadingLabel.Location = new System.Drawing.Point(462, 142);
            this.LoadingLabel.Name = "LoadingLabel";
            this.LoadingLabel.Size = new System.Drawing.Size(10, 13);
            this.LoadingLabel.TabIndex = 7;
            this.LoadingLabel.Text = " ";
            this.LoadingLabel.TextAlign = System.Drawing.ContentAlignment.MiddleCenter;
            // 
            // BlockAll
            // 
            this.BlockAll.Font = new System.Drawing.Font("Roboto Condensed", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.BlockAll.Location = new System.Drawing.Point(461, 83);
            this.BlockAll.Margin = new System.Windows.Forms.Padding(2, 3, 2, 3);
            this.BlockAll.Name = "BlockAll";
            this.BlockAll.Size = new System.Drawing.Size(100, 52);
            this.BlockAll.TabIndex = 8;
            this.BlockAll.Text = "Block All";
            this.BlockAll.UseVisualStyleBackColor = true;
            this.BlockAll.Click += new System.EventHandler(this.BlockAll_Click);
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Font = new System.Drawing.Font("Roboto Condensed", 9.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label2.Location = new System.Drawing.Point(477, 507);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(62, 15);
            this.label2.TabIndex = 9;
            this.label2.Text = "roozbehi.ir";
            this.label2.TextAlign = System.Drawing.ContentAlignment.MiddleCenter;
            // 
            // Form1
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(5F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(916, 651);
            this.Controls.Add(this.label2);
            this.Controls.Add(this.BlockAll);
            this.Controls.Add(this.LoadingLabel);
            this.Controls.Add(this.label1);
            this.Controls.Add(this.Refresh);
            this.Controls.Add(this.Unblock);
            this.Controls.Add(this.Block);
            this.Controls.Add(this.blockedIpAddresses);
            this.Controls.Add(this.titleLabel);
            this.Controls.Add(this.ipListBox);
            this.Font = new System.Drawing.Font("Roboto Condensed", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.Margin = new System.Windows.Forms.Padding(2, 3, 2, 3);
            this.Name = "Form1";
            this.Text = "Brute-Force Blocker";
            this.Load += new System.EventHandler(this.Form1_Load);
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.ListBox ipListBox;
        private System.Windows.Forms.Label titleLabel;
        private System.Windows.Forms.ListBox blockedIpAddresses;
        private System.Windows.Forms.Button Block;
        private System.Windows.Forms.Button Unblock;
        private System.Windows.Forms.Button Refresh;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.Label LoadingLabel;
        private System.Windows.Forms.Button BlockAll;
        private System.Windows.Forms.Label label2;
    }
}

