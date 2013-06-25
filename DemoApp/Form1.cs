using System;
using System.IO;
using System.Windows.Forms;

namespace DemoApp
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            if(openFileDialog1.ShowDialog() == DialogResult.OK)
            {
                textBox1.Text = openFileDialog1.FileName;
                if (File.Exists(textBox1.Text) && File.Exists(textBox2.Text))
                    EasyHookWrapper.Start(textBox1.Text, textBox2.Text);
            }
        }

        private void button2_Click(object sender, EventArgs e)
        {
            if (openFileDialog1.ShowDialog() == DialogResult.OK)
            {
                textBox2.Text = openFileDialog1.FileName;
                if (File.Exists(textBox1.Text) && File.Exists(textBox2.Text))
                    EasyHookWrapper.Start(textBox1.Text, textBox2.Text);
            }
        }
    }
}
